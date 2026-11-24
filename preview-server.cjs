const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { createHmac, createHash, timingSafeEqual, randomBytes } = require('node:crypto');

const ROOT = __dirname;
const projectAssistant = require('./api/project-assistant.js');
try {
  const localEnv = fs.readFileSync(path.join(ROOT,'.env.local'),'utf8');
  for (const line of localEnv.split(/\r?\n/)) {
    const match = line.match(/^\s*(OPENAI_API_KEY|OPENAI_MODEL|WORKSPACE_USERNAME|WORKSPACE_PASSWORD_SHA256|WORKSPACE_SESSION_SECRET)\s*=\s*(.*)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g,'');
  }
} catch {}
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 4173);
const USERNAME = process.env.WORKSPACE_USERNAME || '';
const PASSWORD_SHA256 = process.env.WORKSPACE_PASSWORD_SHA256 || '';
const SECRET = process.env.WORKSPACE_SESSION_SECRET || randomBytes(32).toString('hex');
const COOKIE = 'altop-workspace-session';
const mime = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.jfif':'image/jpeg','.svg':'image/svg+xml','.mp4':'video/mp4','.webp':'image/webp','.pdf':'application/pdf' };
const sign = timestamp => createHmac('sha256', SECRET).update(`altop-workspace:${timestamp}`).digest('base64url');
const cookieValue = req => Object.fromEntries((req.headers.cookie || '').split(';').map(part => { const i=part.indexOf('='); return i<0?['','']:[part.slice(0,i).trim(),part.slice(i+1).trim()]; }))[COOKIE] || '';
const isAuthenticated = req => { const [ts,sig='']=cookieValue(req).split('.'); if(!/^\d+$/.test(ts))return false; const age=Math.floor(Date.now()/1000)-Number(ts); if(age<0||age>28800)return false; const a=Buffer.from(sig),b=Buffer.from(sign(ts)); return a.length===b.length&&timingSafeEqual(a,b); };
const json=(res,status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname==='/api/workspace-auth'){
    if(req.method==='GET')return json(res,200,{authenticated:isAuthenticated(req)});
    if(req.method!=='POST'){res.setHeader('Allow','GET, POST');return json(res,405,{error:'Method not allowed'});}
    let body='';req.on('data',chunk=>{body+=chunk;if(body.length>8192)req.destroy()});req.on('end',()=>{let data={};try{data=JSON.parse(body||'{}')}catch(_){return json(res,400,{error:'Invalid JSON'})}
      if(data.action==='logout'){res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','Set-Cookie':`${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`});return res.end('{"authenticated":false}');}
      const actual=createHash('sha256').update(String(data.password||''),'utf8').digest('hex');const matches=/^[a-f0-9]{64}$/i.test(PASSWORD_SHA256)&&timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(PASSWORD_SHA256,'hex'));
      if(data.action!=='login'||data.username!==USERNAME||!matches)return json(res,401,{authenticated:false});
      const ts=String(Math.floor(Date.now()/1000));res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','Set-Cookie':`${COOKIE}=${ts}.${sign(ts)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800`});res.end(JSON.stringify({authenticated:true,username:USERNAME}));
    });return;
  }
  if(url.pathname==='/api/project-assistant'){
    if(req.method!=='POST'){res.setHeader('Allow','POST');return json(res,405,{error:'استخدم طلب POST.'});}
    let body='';req.on('data',chunk=>{body+=chunk;if(body.length>100000)req.destroy()});
    req.on('end',async()=>{try{req.body=JSON.parse(body||'{}')}catch{return json(res,400,{error:'تعذر قراءة الطلب.'})}
      const response={status(code){return {json(data){return json(res,code,data)}}}};
      try{await projectAssistant(req,response)}catch{return json(res,502,{error:'تعذر تشغيل المساعد.'})}
    });return;
  }
  if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);return res.end();}
  let pathname;try{pathname=decodeURIComponent(url.pathname)}catch(_){res.writeHead(400);return res.end();}
  if(pathname==='/')pathname='/index.html';
  const filename=path.resolve(ROOT,`.${pathname}`);
  if(filename!==ROOT&&!filename.startsWith(ROOT+path.sep)){res.writeHead(403);return res.end();}
  fs.stat(filename,(err,stat)=>{if(err||!stat.isFile()){res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});return res.end('Not found');}
    res.writeHead(200,{'Content-Type':mime[path.extname(filename).toLowerCase()]||'application/octet-stream','Content-Length':stat.size,'Cache-Control':'no-cache'});
    if(req.method==='HEAD')return res.end();fs.createReadStream(filename).pipe(res);
  });
});
server.listen(PORT,HOST,()=>console.log(`Al_Top local preview: http://localhost:${PORT}/`));
