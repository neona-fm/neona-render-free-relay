// Neona Render Free Relay. Authenticated VLESS-over-WebSocket, TCP 80/443 only.
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';
import {WebSocketServer, WebSocket} from 'ws';

const port = Number(process.env.PORT || 10000);
const uuid = (process.env.VLESS_UUID || '').toLowerCase();
const path = process.env.VLESS_PATH || '/private';
const MAX_HANDSHAKE = 65536;
const WS_BUFFER_LIMIT = 4 * 1024 * 1024;

function isPublicIP(address) {
  if (net.isIP(address) === 4) {
    const p = address.split('.').map(Number), [a,b] = p;
    return !(a===0 || a===10 || a===127 || a>=224 ||
      (a===100 && b>=64 && b<=127) || (a===169 && b===254) ||
      (a===172 && b>=16 && b<=31) || (a===192 && b===168) ||
      (a===192 && b===0 && (p[2]===0 || p[2]===2)) ||
      (a===198 && (b===18 || b===19 || (b===51 && p[2]===100))) ||
      (a===203 && b===0 && p[2]===113));
  }
  if (net.isIP(address) === 6) {
    const s=address.toLowerCase();
    return !(s==='::' || s==='::1' || s.startsWith('fc') || s.startsWith('fd') ||
       /^fe[89ab]/.test(s) || s.startsWith('ff') || s.startsWith('2001:db8:') ||
       s.startsWith('::ffff:'));
  }
  return false;
}
function parseHandshake(b) {
  if (b.length<22) return null;
  if (b[0]!==0) throw Error('Unsupported VLESS version');
  const h=b.subarray(1,17).toString('hex');
  const id=[h.slice(0,8),h.slice(8,12),h.slice(12,16),h.slice(16,20),h.slice(20)].join('-');
  if (id!==uuid) throw Error('Wrong UUID');
  let off=18+b[17];
  if (b.length<off+4) return null;
  const cmd=b[off], destinationPort=b.readUInt16BE(off+1), type=b[off+3];
  if(cmd!==1 || ![80,443].includes(destinationPort)) throw Error('TCP 80/443 only');
  off+=4;
  let host;
  if(type===1) {
    if(b.length<off+4)return null;
    host=[...b.subarray(off,off+4)].join('.');off+=4;
  } else if(type===2) {
    if(b.length<off+1)return null;
    const len=b[off++];
    if(!len || b.length<off+len)return null;
    host=b.subarray(off,off+len).toString('utf8');off+=len;
  } else if(type===3) {
    if(b.length<off+16)return null;
    const arr=[];for(let i=0;i<8;i++)arr.push(b.readUInt16BE(off+i*2).toString(16));
    host=arr.join(':');off+=16;
  } else throw Error('Bad address type');
  return {host,port:destinationPort,payload:b.subarray(off)};
}
async function resolvePublic(host) {
  if(net.isIP(host)) {
    if(!isPublicIP(host))throw Error('Private destination');
    return {address:host,family:net.isIP(host)};
  }
  if(!/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(host) || host.length>253)throw Error('Invalid domain');
  const addrs=await dns.lookup(host,{all:true,verbatim:true});
  const match=addrs.find(x=>isPublicIP(x.address));
  if(!match)throw Error('No public destination');
  return match;
}
if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid))
  throw Error('Set VLESS_UUID');
if(!/^\/[A-Za-z0-9/_-]{4,100}$/.test(path)) throw Error('Set secure VLESS_PATH');

const app=http.createServer((req,res)=>{
  const ok=req.url==='/health';
  res.writeHead(ok?200:404,{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'});
  res.end(ok?'ok':'Not found');
});
const wss=new WebSocketServer({noServer:true,maxPayload:1024*1024,perMessageDeflate:false});
app.on('upgrade',(req,socket,head)=>{
  if(req.url?.split('?')[0]!==path) {socket.destroy();return;}
  wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws));
});
wss.on('connection',ws=>{
  let ready=false,pending=Buffer.alloc(0),remote=null,finishing=false,connecting=false;
  let bytesPending=[];
  const finish=()=>{
    if(finishing)return;finishing=true;
    try{remote?.destroy()}catch{}
    try{ws.close()}catch{}
  };
  async function startConnection(){
    try{
      const data=parseHandshake(pending);
      if(!data)return;
      const addr=await resolvePublic(data.host);
      const sock=net.createConnection({host:addr.address,port:data.port,family:addr.family});
      sock.setTimeout(120000,finish);
      sock.once('connect',()=>{
        if(finishing){sock.destroy();return;}
        remote=sock;ready=true;
        ws.send(Buffer.from([0,0]));
        if(data.payload.length)sock.write(data.payload);
        for(const p of bytesPending)sock.write(p);
        bytesPending=[];
      });
      sock.on('data',chunk=>{
        if(ws.readyState===WebSocket.OPEN){
          if(ws.bufferedAmount>WS_BUFFER_LIMIT)sock.pause();
          ws.send(chunk,{binary:true},()=>{if(!finishing)sock.resume()});
        }
      });
      sock.on('error',finish);
      sock.on('close',finish);
    }catch{finish();}
  }
  ws.on('message',(b,isBinary)=>{
    if(!isBinary){finish();return;}
    if(ready){remote?.write(b);return;}
    if(connecting){
      if(bytesPending.reduce((n,x)=>n+x.length,0)+b.length>MAX_HANDSHAKE){finish();return;}
      bytesPending.push(Buffer.from(b));return;
    }
    pending=Buffer.concat([pending,b]);
    if(pending.length>MAX_HANDSHAKE){finish();return;}
    try{if(parseHandshake(pending)){connecting=true;void startConnection();}}catch{finish();}
  });
  ws.on('close',finish);
  ws.on('error',finish);
});
app.listen(port,'0.0.0.0',()=>console.log('Relay listening on '+port));
