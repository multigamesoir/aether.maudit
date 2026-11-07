// Serveur Aethergard : sert le jeu + relaie les messages entre les 2 joueurs (WebSocket).
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {WebSocketServer}=require('ws');
const PORT=process.env.PORT||3000, ROOT=__dirname;
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript','.mp3':'audio/mpeg','.ogg':'audio/ogg','.png':'image/png','.json':'application/json','.css':'text/css'};

/* ===================== COMPTES & SAUVEGARDES ===================== */
const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,'data');
const UP_URL=process.env.UPSTASH_REDIS_REST_URL,UP_TOKEN=process.env.UPSTASH_REDIS_REST_TOKEN;
let store;
if(UP_URL&&UP_TOKEN){ // stockage persistant gratuit (Upstash Redis)
  const up=async cmd=>{const r=await fetch(UP_URL,{method:'POST',headers:{Authorization:'Bearer '+UP_TOKEN,'Content-Type':'application/json'},body:JSON.stringify(cmd)});const j=await r.json();if(j.error)throw new Error(j.error);return j.result};
  store={kind:'upstash',get:async k=>{const v=await up(['GET','aeg:'+k]);return v?JSON.parse(v):null},set:async(k,v)=>{await up(['SET','aeg:'+k,JSON.stringify(v)])},
    del:async k=>{await up(['DEL','aeg:'+k])},
    keys:async()=>{let cur='0';const out=[];do{const r=await up(['SCAN',cur,'MATCH','aeg:*','COUNT','500']);cur=String(r[0]);for(const k of r[1])out.push(k.slice(4))}while(cur!=='0'&&out.length<5000);return [...new Set(out)]},
    getMany:async ks=>{const o={};for(let i=0;i<ks.length;i+=100){const part=ks.slice(i,i+100);const r=await up(['MGET',...part.map(k=>'aeg:'+k)]);part.forEach((k,j)=>{try{if(r[j])o[k]=JSON.parse(r[j])}catch(e){}})}return o}};
}else{ // fichier local (⚠ effacé par Render gratuit à chaque redémarrage/déploiement, sauf disque persistant)
  const F=path.join(DATA_DIR,'accounts.json');let db={},t=null;
  try{fs.mkdirSync(DATA_DIR,{recursive:true});db=JSON.parse(fs.readFileSync(F,'utf8'))}catch(e){}
  const flush=()=>{t=null;try{fs.writeFileSync(F+'.tmp',JSON.stringify(db));fs.renameSync(F+'.tmp',F)}catch(e){console.error('save db',e.message)}};
  store={kind:'file',get:async k=>db[k]||null,set:async(k,v)=>{db[k]=v;if(!t)t=setTimeout(flush,800)},
    del:async k=>{delete db[k];if(!t)t=setTimeout(flush,800)},
    keys:async()=>Object.keys(db),
    getMany:async ks=>{const o={};for(const k of ks)if(db[k])o[k]=db[k];return o}};
}
console.log('Stockage des comptes :',store.kind);
const sessions=new Map(); // token -> key
const fails=new Map();    // ip -> {n,t}
const hashPw=(pw,salt)=>crypto.scryptSync(String(pw),salt,32).toString('hex');
const okName=n=>/^[A-Za-z0-9_\-]{3,12}$/.test(n);
function ipOf(req){return (req.headers['x-forwarded-for']||req.socket.remoteAddress||'?').toString().split(',')[0].trim()}
function blocked(ip){const f=fails.get(ip);return f&&f.n>=10&&Date.now()-f.t<10*60*1000}
function fail(ip){const f=fails.get(ip)||{n:0,t:0};if(Date.now()-f.t>10*60*1000)f.n=0;f.n++;f.t=Date.now();fails.set(ip,f)}
function readBody(req){return new Promise((res,rej)=>{let b='';req.on('data',c=>{b+=c;if(b.length>300000){rej(new Error('big'));req.destroy()}});req.on('end',()=>res(b));req.on('error',rej)})}
function json(res,code,o){res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(o))}
async function api(req,res,u){
  if(req.method!='POST')return json(res,405,{err:'POST seulement'});
  let b;try{b=JSON.parse(await readBody(req))}catch(e){return json(res,400,{err:'Requête invalide'})}
  const ip=ipOf(req);
  try{
    if(u=='/api/register'||u=='/api/login'){
      const name=String(b.name||'').trim(),pw=String(b.pass||'');
      if(!okName(name))return json(res,400,{err:'Pseudo : 3 à 12 caractères (lettres, chiffres, _ ou -).'});
      if(pw.length<4||pw.length>64)return json(res,400,{err:'Mot de passe : 4 caractères minimum.'});
      if(u=='/api/login'&&blocked(ip))return json(res,429,{err:'Trop d\'essais. Réessaie dans 10 minutes.'}); // plus aucune limite à la création de compte
      const key=name.toLowerCase();let acc=await store.get(key);
      if(u=='/api/register'){
        if(acc)return json(res,409,{err:'Ce pseudo existe déjà. Utilise SE CONNECTER.'});
        const salt=crypto.randomBytes(16).toString('hex');
        acc={name,salt,hash:hashPw(pw,salt),save:null,pend:[],created:Date.now(),glow:false};await store.set(key,acc);
      }else{
        if(!acc){fail(ip);return json(res,404,{err:'Compte introuvable. Clique sur CRÉER LE COMPTE.'})}
        const a=Buffer.from(hashPw(pw,acc.salt),'hex'),h=Buffer.from(acc.hash,'hex');
        if(a.length!=h.length||!crypto.timingSafeEqual(a,h)){fail(ip);return json(res,401,{err:'Mot de passe incorrect.'})}
      }
      const token=crypto.randomBytes(18).toString('hex');sessions.set(token,key);
      return json(res,200,{ok:1,name:acc.name,token,save:acc.save,gifts:acc.pend||[],created:u=='/api/register',glow:!!acc.glow});
    }
    if(u=='/api/save'){
      const key=sessions.get(String(b.token||''));if(!key)return json(res,401,{err:'Session expirée'});
      if(!b.save||typeof b.save!='object'||JSON.stringify(b.save).length>120000)return json(res,400,{err:'Sauvegarde invalide'});
      return await withLock(key,async()=>{
        const acc=await store.get(key);if(!acc)return json(res,404,{err:'Compte introuvable'});
        acc.save=b.save;
        if(Array.isArray(b.ack)&&acc.pend&&acc.pend.length){const ak=new Set(b.ack.filter(x=>typeof x=='string'));acc.pend=acc.pend.filter(g=>!ak.has(g.id))}
        await store.set(key,acc);return json(res,200,{ok:1,gifts:acc.pend||[],glow:!!acc.glow})});
    }
    if(u=='/api/gifts'){
      const key=sessions.get(String(b.token||''));if(!key)return json(res,401,{err:'Session expirée'});
      const acc=await store.get(key);if(!acc)return json(res,404,{err:'Compte introuvable'});
      return json(res,200,{ok:1,gifts:acc.pend||[],glow:!!acc.glow});
    }
    return json(res,404,{err:'Inconnu'});
  }catch(e){console.error('api',e.message);return json(res,500,{err:'Erreur serveur'})}
}


/* ===================== MUTEX PAR COMPTE (évite que 2 écritures simultanées s'écrasent) ===================== */
const locks=new Map();
function withLock(k,fn){const prev=locks.get(k)||Promise.resolve();const run=prev.then(fn);const tail=run.catch(()=>{});locks.set(k,tail);tail.then(()=>{if(locks.get(k)===tail)locks.delete(k)});return run}

/* ===================== ADMIN (réservé au propriétaire) =====================
   - Le mot de passe n'est JAMAIS dans le code : variable d'environnement ADMIN_PASSWORD (Render > Environment), 10 caractères minimum.
   - Toutes les actions sont vérifiées ICI, côté serveur, avec un jeton aléatoire (2 h). Lire le code de la page ne donne aucun accès.
   - Blocage : 5 essais ratés / IP / 15 min et 10 essais ratés au total / 15 min. */
const ADMIN_PW=process.env.ADMIN_PASSWORD||'';
const ADMIN_OK=ADMIN_PW.length>=10;
const ADMIN_SALT=crypto.randomBytes(16).toString('hex');
const ADMIN_HASH=ADMIN_OK?Buffer.from(hashPw(ADMIN_PW,ADMIN_SALT),'hex'):null;
console.log(!ADMIN_PW?'Admin : désactivé (ADMIN_PASSWORD non défini)':!ADMIN_OK?'Admin : DÉSACTIVÉ (ADMIN_PASSWORD trop court : 10 caractères minimum)':'Admin : activé sur /admin');
const adminSessions=new Map(),ADM_TTL=2*3600*1000,admFails=new Map();let admFailG={n:0,t:0};
function ipLast(req){const x=(req.headers['x-forwarded-for']||'').toString().split(',').map(v=>v.trim()).filter(Boolean);return x.length?x[x.length-1]:(req.socket.remoteAddress||'?')}
function admBlocked(ip){const now=Date.now();if(admFailG.n>=10&&now-admFailG.t<15*60e3)return true;const f=admFails.get(ip);return !!f&&f.n>=5&&now-f.t<15*60e3}
function admFail(ip){const now=Date.now();if(now-admFailG.t>15*60e3)admFailG.n=0;admFailG.n++;admFailG.t=now;const f=admFails.get(ip)||{n:0,t:0};if(now-f.t>15*60e3)f.n=0;f.n++;f.t=now;admFails.set(ip,f)}
function admAuth(req){const t=String(req.headers['x-admin-token']||'');const e=adminSessions.get(t);if(!e)return false;if(Date.now()>e){adminSessions.delete(t);return false}return true}
/* Catalogue utilisé par le panneau admin (à compléter quand tu ajoutes un héros / monstre / sort au jeu) : [identifiant, nom, prix] */
const CATALOG={
  heroes:[['el',"Soldat d'Élite",50],['ar','Archer',75],['wa','Apprenti Sorcier',100],['dr','Druide',150],['che','Chevalier',250],['fi','Sorcier de feu',300],['xb','Arbalétrier',400],['li','Sorcier de foudre',500],['pa','Paladin',600],['nb','Assassin Magique',800],['kh','Héros Chevalier',800],['vi','Viking',800],['kg','Roi',1000]],
  monsters:[[2,'Chauve-souris',50],[1,'Étourdisseur',80],[10,'Oeil volant',80],[11,'Sporeux',100],[9,'Squelette',100],[18,'Gobelin Élite',100],[15,'Slime',250],[14,'Mimic',300],[12,'Invocateur',400],[13,'Général',500],[19,'Nécromancien',500],[4,'Golem de glace',700],[21,'Bourreau',900],[17,'Guardian',1000],[23,'Le Maudit',600]],
  spells:[[0,'Foudre',100],[1,'Nécromancie',600]],
  equip:[[0,'Potion de soin',150],[1,'Cristal de rapidité',150]],
  levels:15,arMax:10};
const ADD_KEYS=new Set(['coins','acoins','kKeys','ARL','OBL','AUP']),OWN_TABS=new Set(['heroOwned','aeOwned','spOwned','eqK','eqA']),LV_TABS=new Set(['lvDone','lvDoneA']);
function cleanOps(ops){if(!Array.isArray(ops)||!ops.length||ops.length>300)return null;const out=[];
  for(const o of ops){if(!Array.isArray(o))return null;const k=o[0];
    if(k=='add'){const v=Math.round(Number(o[2]));if(!ADD_KEYS.has(o[1])||!Number.isFinite(v)||Math.abs(v)>10000000)return null;if(v)out.push(['add',o[1],v])}
    else if(k=='own'){const id=String(o[3]);if(!OWN_TABS.has(o[1])||!/^[A-Za-z0-9_]{1,12}$/.test(id))return null;out.push(['own',o[1],o[2]?1:0,id])}
    else if(k=='lv'){const L=Math.round(Number(o[3]));if(!LV_TABS.has(o[1])||!(L>=1&&L<=99))return null;out.push(['lv',o[1],o[2]?1:0,String(L)])}
    else return null}
  return out.length?out:null}
async function adminApi(req,res,u){
  if(req.method!='POST')return json(res,405,{err:'POST seulement'});
  if(!ADMIN_OK)return json(res,503,{err:'Admin désactivé : définis ADMIN_PASSWORD (10 caractères minimum) dans Render > Environment.'});
  let b;try{b=JSON.parse(await readBody(req))}catch(e){return json(res,400,{err:'Requête invalide'})}
  const ip=ipLast(req);
  try{
    if(u=='/api/admin/login'){
      if(admBlocked(ip))return json(res,429,{err:'Trop d\'essais. Réessaie dans 15 minutes.'});
      const h=Buffer.from(hashPw(String(b.pass||'').slice(0,200),ADMIN_SALT),'hex');
      if(!crypto.timingSafeEqual(h,ADMIN_HASH)){admFail(ip);await new Promise(r=>setTimeout(r,700));return json(res,401,{err:'Mot de passe incorrect.'})}
      admFailG.n=0;admFails.delete(ip);
      const token=crypto.randomBytes(32).toString('hex');adminSessions.set(token,Date.now()+ADM_TTL);
      return json(res,200,{ok:1,token,store:store.kind,catalog:CATALOG});
    }
    if(!admAuth(req))return json(res,401,{err:'Session admin expirée. Reconnecte-toi.'});
    if(u=='/api/admin/logout'){adminSessions.delete(String(req.headers['x-admin-token']||''));return json(res,200,{ok:1})}
    if(u=='/api/admin/list'){
      const ks=await store.keys(),all=await store.getMany(ks),rows=[];
      for(const k of ks){const a=all[k];if(!a)continue;const s=(a.save&&a.save.s)||{};
        rows.push({name:a.name||k,created:a.created||0,ts:(a.save&&a.save.ts)||0,coins:Math.round(+s.coins||0),heroes:Object.keys(s.heroOwned||{}).length,pend:(a.pend||[]).length,glow:!!a.glow})}
      rows.sort((x,y)=>y.ts-x.ts||x.name.localeCompare(y.name));
      return json(res,200,{ok:1,accounts:rows});
    }
    const name=String(b.name||'').trim(),key=name.toLowerCase();
    if(!okName(name))return json(res,400,{err:'Pseudo invalide'});
    if(u=='/api/admin/get'){
      const a=await store.get(key);if(!a)return json(res,404,{err:'Compte introuvable'});
      return json(res,200,{ok:1,name:a.name,created:a.created||0,save:a.save||null,pend:a.pend||[],glow:!!a.glow});
    }
    if(u=='/api/admin/create'){ // création de compte forcée (aucune limite)
      const pw=String(b.pass||'');if(pw.length<4||pw.length>64)return json(res,400,{err:'Mot de passe : 4 à 64 caractères.'});
      return await withLock(key,async()=>{if(await store.get(key))return json(res,409,{err:'Ce pseudo existe déjà.'});
        const salt=crypto.randomBytes(16).toString('hex');
        await store.set(key,{name,salt,hash:hashPw(pw,salt),save:null,pend:[],created:Date.now(),glow:!!b.glow});
        return json(res,200,{ok:1,name})});
    }
    if(u=='/api/admin/setglow'){ // Glow Mode du pseudo
      return await withLock(key,async()=>{const a=await store.get(key);if(!a)return json(res,404,{err:'Compte introuvable'});
        a.glow=!!b.glow;await store.set(key,a);return json(res,200,{ok:1,glow:a.glow})});
    }
    if(u=='/api/admin/give'){
      const ops=cleanOps(b.ops);if(!ops)return json(res,400,{err:'Modifications invalides'});
      return await withLock(key,async()=>{const a=await store.get(key);if(!a)return json(res,404,{err:'Compte introuvable'});
        a.pend=a.pend||[];if(a.pend.length>=50)return json(res,400,{err:'Trop de cadeaux en attente pour ce compte (50 max). Annule-en ou attends que le joueur se connecte.'});
        const id='g'+Date.now().toString(36)+crypto.randomBytes(3).toString('hex');
        a.pend.push({id,at:Date.now(),ops});await store.set(key,a);return json(res,200,{ok:1,id})});
    }
    if(u=='/api/admin/cancel'){
      return await withLock(key,async()=>{const a=await store.get(key);if(!a)return json(res,404,{err:'Compte introuvable'});
        a.pend=(a.pend||[]).filter(g=>g.id!==String(b.id));await store.set(key,a);return json(res,200,{ok:1})});
    }
    if(u=='/api/admin/setpass'){
      const pw=String(b.pass||'');if(pw.length<4||pw.length>64)return json(res,400,{err:'Mot de passe : 4 à 64 caractères.'});
      return await withLock(key,async()=>{const a=await store.get(key);if(!a)return json(res,404,{err:'Compte introuvable'});
        a.salt=crypto.randomBytes(16).toString('hex');a.hash=hashPw(pw,a.salt);await store.set(key,a);
        for(const [t,k] of sessions)if(k===key)sessions.delete(t);return json(res,200,{ok:1})});
    }
    if(u=='/api/admin/delete'){
      if(String(b.confirm||'').trim().toLowerCase()!==key)return json(res,400,{err:'Confirmation incorrecte.'});
      return await withLock(key,async()=>{await store.del(key);for(const [t,k] of sessions)if(k===key)sessions.delete(t);return json(res,200,{ok:1})});
    }
    return json(res,404,{err:'Inconnu'});
  }catch(e){console.error('admin',e.message);return json(res,500,{err:'Erreur serveur'})}
}
const ADMIN_HTML=String.raw`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Aethergard - Admin</title>
<style>
:root{color-scheme:dark;--bg:#0b0a16;--card:#15132a;--line:#2c2860;--txt:#e9e6ff;--mut:#9c97c8;--ok:#3ecf6e;--bad:#ff5a6a;--acc:#ffd45a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.4 system-ui,Segoe UI,Roboto,sans-serif}
button,input{font:inherit}button{background:#2a2670;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 14px;cursor:pointer}
button:hover{background:#3a3590}button.p{background:#1d8a4a;border-color:#2cb866}button.d{background:#8a1d2c;border-color:#c0394d}button.s{padding:4px 9px;font-size:13px}
input[type=text],input[type=password],input[type=number]{background:#0e0c20;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 10px;width:100%}
.top{display:flex;gap:10px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);flex-wrap:wrap}.top h1{font-size:18px;margin:0;flex:1;color:var(--acc)}
.badge{padding:3px 10px;border-radius:99px;font-size:12px;border:1px solid var(--line)}.badge.ok{color:var(--ok);border-color:var(--ok)}.badge.bad{color:var(--bad);border-color:var(--bad)}
.warn{background:#3a1018;border:1px solid var(--bad);color:#ffc9cf;padding:10px 14px;margin:10px 14px;border-radius:8px}
.info{background:#10223a;border:1px solid #2c5a96;color:#bcd9ff;padding:8px 12px;border-radius:8px;margin-bottom:12px;font-size:13px}
.wrap{display:grid;grid-template-columns:300px 1fr;gap:14px;padding:14px}@media(max-width:800px){.wrap{grid-template-columns:1fr}}
.box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px}
.list{max-height:72vh;overflow:auto;margin-top:8px}.row{padding:8px 10px;border-radius:8px;cursor:pointer;border:1px solid transparent}.row:hover{background:#1f1c44}.row.sel{background:#2a2670;border-color:var(--acc)}
.row b{display:block}.row span{color:var(--mut);font-size:12px}
h2{font-size:16px;margin:0 0 6px}h3{font-size:14px;margin:16px 0 6px;color:var(--acc)}.mut{color:var(--mut)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:6px}
.num{display:flex;gap:8px;align-items:center;background:#0e0c20;border:1px solid var(--line);border-radius:8px;padding:6px 10px}.num label{flex:1}.num input{width:110px}.num small{display:block;color:var(--mut)}
.chk{display:flex;gap:8px;align-items:center;padding:6px 10px;background:#0e0c20;border:1px solid var(--line);border-radius:8px;cursor:pointer;user-select:none}
.chk.give{border-color:var(--ok);background:#0f2a1a}.chk.take{border-color:var(--bad);background:#2a0f16}.chk input{width:18px;height:18px}
.pend{display:flex;gap:8px;align-items:center;justify-content:space-between;padding:6px 10px;border:1px dashed var(--line);border-radius:8px;margin-bottom:6px;font-size:13px}
.login{max-width:360px;margin:12vh auto;padding:20px}.err{color:var(--bad);min-height:20px;margin-top:8px}
.bar{display:flex;gap:6px;margin:4px 0 6px}.sticky{position:sticky;bottom:0;background:var(--card);padding:10px 0;border-top:1px solid var(--line);margin-top:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
#msg{color:var(--ok);font-size:13px}
.gn-glow{font-weight:800;background:linear-gradient(90deg,#ffe27a,#ff7ad9,#7fa8ff,#7dffd0,#ffe27a);background-size:300% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent;animation:gnSlide 3s linear infinite,gnPulse 1.6s ease-in-out infinite alternate}
@keyframes gnSlide{to{background-position:300% 0}}
@keyframes gnPulse{from{filter:drop-shadow(0 0 2px #ffe27a) drop-shadow(0 0 5px #7fa8ff)}to{filter:drop-shadow(0 0 5px #ff7ad9) drop-shadow(0 0 12px #7dffd0)}}
.glowbox{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 12px;background:#0e0c20;border:1px solid var(--line);border-radius:8px}
.glowbox .chk{border:0;padding:0;background:none}
.create{margin-top:10px;display:grid;gap:6px}
</style></head><body><div id="app"></div>
<script>
var TOKEN='',CAT=null,STORE='',ACCS=[],CUR=null,DATA=null,INIT={};
var NUM=[['coins','Pi\u00e8ces (Royaume)'],['acoins','Pi\u00e8ces Aether'],['kKeys','Cl\u00e9s'],['ARL','Niveau de l\u2019archer'],['OBL','Niveau de l\u2019ob\u00e9lisque'],['AUP','Puissance des monstres']];
function $(i){return document.getElementById(i)}
function h(tag,props,kids){var e=document.createElement(tag);if(props)for(var k in props){if(k=='class')e.className=props[k];else if(k=='text')e.textContent=props[k];else if(k.slice(0,2)=='on')e[k]=props[k];else e.setAttribute(k,props[k])}
 (kids||[]).forEach(function(c){if(c!=null)e.appendChild(typeof c=='string'?document.createTextNode(c):c)});return e}
function call(path,body){return fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':TOKEN},body:JSON.stringify(body||{})}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){
 if(!r.ok){if(r.status==401&&TOKEN&&path!='/api/admin/login'){TOKEN='';sessionStorage.removeItem('adm');login('Session expir\u00e9e, reconnecte-toi.')}throw new Error(j.err||('Erreur '+r.status))}return j})})}
function login(msg){$('app').innerHTML='';var pw=h('input',{type:'password',placeholder:'Mot de passe admin',autocomplete:'current-password'}),er=h('div',{class:'err',text:msg||''});
 function go(){er.textContent='Connexion...';call('/api/admin/login',{pass:pw.value}).then(function(j){TOKEN=j.token;CAT=j.catalog;STORE=j.store;sessionStorage.setItem('adm',JSON.stringify({t:j.token,c:j.catalog,s:j.store}));pw.value='';main()}).catch(function(e){er.textContent=e.message})}
 pw.onkeydown=function(e){if(e.key=='Enter')go()};
 $('app').appendChild(h('div',{class:'box login'},[h('h2',{text:'Aethergard - Administration'}),h('p',{class:'mut',text:'Acc\u00e8s r\u00e9serv\u00e9.'}),pw,h('div',{style:'height:10px'}),h('button',{class:'p',text:'Connexion',onclick:go}),er]));pw.focus()}
function logout(){call('/api/admin/logout').catch(function(){});TOKEN='';sessionStorage.removeItem('adm');login('')}
function fmt(t){return t?new Date(t).toLocaleString('fr-FR'):'jamais'}
function nm(tab,id){var L=tab=='h'?CAT.heroes:CAT.monsters;for(var i=0;i<L.length;i++)if(String(L[i][0])==String(id))return L[i][1];return id}
function opText(o){var k=o[0];
 if(k=='add')return(o[2]>0?'+':'')+o[2]+' '+({coins:'pi\u00e8ces',acoins:'pi\u00e8ces Aether',kKeys:'cl\u00e9s',ARL:'niv. archer',OBL:'niv. ob\u00e9lisque',AUP:'puissance monstres'})[o[1]];
 var v=o[2]?'donne ':'retire ';
 if(k=='own'){var t=o[1];if(t=='heroOwned')return v+'h\u00e9ros '+nm('h',o[3]);if(t=='aeOwned')return v+'monstre '+nm('m',o[3]);if(t=='spOwned')return v+'sort '+CAT.spells[+o[3]][1];if(t=='eqK')return v+'\u00e9quipement royaume '+CAT.equip[+o[3]][1];if(t=='eqA')return v+'\u00e9quipement Aether '+CAT.equip[+o[3]][1]}
 if(k=='lv')return v+'niveau '+(o[1]=='lvDoneA'?'Aether ':'Royaume ')+o[3]+' termin\u00e9';return JSON.stringify(o)}
function effective(){var s=JSON.parse(JSON.stringify((DATA.save&&DATA.save.s)||{}));
 s.heroOwned=s.heroOwned||{};s.aeOwned=s.aeOwned||{};s.spOwned=s.spOwned||{};s.eqOwn=s.eqOwn||{};s.eqOwn.k=s.eqOwn.k||{};s.eqOwn.a=s.eqOwn.a||{};s.lvDone=s.lvDone||{};s.lvDoneA=s.lvDoneA||{};
 ['coins','acoins','kKeys'].forEach(function(k){s[k]=+s[k]||0});s.ARL=+s.ARL||1;s.OBL=+s.OBL||1;s.AUP=+s.AUP||1;
 function setv(t,id,v){if(v)t[id]=1;else delete t[id]}
 (DATA.pend||[]).forEach(function(g){g.ops.forEach(function(o){var k=o[0];
  if(k=='add'){var min=(o[1]=='ARL'||o[1]=='OBL'||o[1]=='AUP')?1:0;s[o[1]]=Math.max(min,s[o[1]]+o[2]);if(o[1]=='ARL')s.ARL=Math.min(CAT.arMax,s.ARL)}
  else if(k=='own'){var t=o[1];setv(t=='heroOwned'?s.heroOwned:t=='aeOwned'?s.aeOwned:t=='spOwned'?s.spOwned:t=='eqK'?s.eqOwn.k:s.eqOwn.a,o[3],o[2])}
  else if(k=='lv')setv(o[1]=='lvDoneA'?s.lvDoneA:s.lvDone,o[3],o[2])})});return s}
function main(){var a=$('app');a.innerHTML='';
 var top=h('div',{class:'top'},[h('h1',{text:'Aethergard - Admin'}),h('span',{class:'badge '+(STORE=='upstash'?'ok':'bad'),text:'Stockage : '+STORE}),h('button',{class:'s',text:'Actualiser',onclick:function(){loadList(true)}}),h('button',{class:'s',text:'D\u00e9connexion',onclick:logout})]);a.appendChild(top);
 if(STORE!='upstash')a.appendChild(h('div',{class:'warn',text:'Attention : le stockage est en mode fichier. Les comptes (et tes modifications) disparaissent \u00e0 chaque red\u00e9ploiement de Render. Configure Upstash (voir LIRE-MOI.md).'}));
 var search=h('input',{type:'text',placeholder:'Rechercher un pseudo...'});search.oninput=function(){renderList(search.value)};
 var left=h('div',{class:'box'},[h('h2',{text:'Comptes'}),createBox(),search,h('div',{class:'list',id:'list'})]);
 var right=h('div',{class:'box',id:'detail'},[h('p',{class:'mut',text:'Choisis un compte \u00e0 gauche.'})]);
 a.appendChild(h('div',{class:'wrap'},[left,right]));loadList(false)}
function createBox(){
 var nameI=h('input',{type:'text',placeholder:'Pseudo (3-12 caract\u00e8res)',maxlength:'12',autocomplete:'off'}),passI=h('input',{type:'text',placeholder:'Mot de passe (4 minimum)',autocomplete:'off'}),
  gcb=h('input',{type:'checkbox'}),er=h('div',{class:'err',style:'min-height:0;font-size:13px'}),form=h('div',{class:'create',style:'display:none'});
 var glab=h('label',{class:'chk'},[gcb,document.createTextNode('Glow Mode d\u00e8s la cr\u00e9ation')]);
 var go=h('button',{class:'p',text:'Cr\u00e9er le compte',onclick:function(){var nm0=nameI.value.trim();er.style.color='#ffd45a';er.textContent='Cr\u00e9ation...';
  call('/api/admin/create',{name:nm0,pass:passI.value,glow:gcb.checked}).then(function(j){er.style.color='#3ecf6e';er.textContent='Compte "'+j.name+'" cr\u00e9\u00e9 !';nameI.value='';passI.value='';gcb.checked=false;
   return call('/api/admin/list').then(function(l){ACCS=l.accounts;renderList('');openAcc(j.name)})}).catch(function(e){er.style.color='#ff5a6a';er.textContent=e.message})}});
 form.appendChild(nameI);form.appendChild(passI);form.appendChild(glab);form.appendChild(go);form.appendChild(er);
 var tg=h('button',{class:'s p',text:'+ Cr\u00e9er un compte (forc\u00e9)',onclick:function(){form.style.display=form.style.display=='none'?'grid':'none'}});
 return h('div',{},[tg,form])}
function loadList(keep){call('/api/admin/list').then(function(j){ACCS=j.accounts;renderList('');if(keep&&CUR)openAcc(CUR)}).catch(function(e){$('list').textContent=e.message})}
function renderList(q){var L=$('list');L.innerHTML='';q=(q||'').toLowerCase();var n=0;
 ACCS.forEach(function(c){if(q&&c.name.toLowerCase().indexOf(q)<0)return;n++;
  var r=h('div',{class:'row'+(CUR==c.name.toLowerCase()?' sel':'')},[h('b',{class:c.glow?'gn-glow':'',text:c.name}),h('span',{text:c.coins+' pi\u00e8ces - '+c.heroes+' h\u00e9ros - '+fmt(c.ts)+(c.pend?' - '+c.pend+' en attente':'')})]);
  r.onclick=function(){openAcc(c.name)};L.appendChild(r)});
 if(!n)L.appendChild(h('p',{class:'mut',text:ACCS.length?'Aucun r\u00e9sultat.':'Aucun compte pour le moment.'}))}
function openAcc(name){CUR=name.toLowerCase();renderList('');$('detail').innerHTML='Chargement...';
 call('/api/admin/get',{name:name}).then(function(j){DATA=j;detail()}).catch(function(e){$('detail').textContent=e.message})}
function chkBlock(title,items,owned,key){
 var box=h('div',{},[h('h3',{text:title})]),bar=h('div',{class:'bar'}),grid=h('div',{class:'grid'}),boxes=[];
 items.forEach(function(it){var id=String(it[0]),was=!!owned[id],lab=h('label',{class:'chk'}),cb=h('input',{type:'checkbox'});cb.checked=was;
  var price=it[2]!=null?' ('+it[2]+')':'';lab.appendChild(cb);lab.appendChild(document.createTextNode(it[1]+price));
  function upd(){lab.className='chk'+(cb.checked!=was?(cb.checked?' give':' take'):'')}cb.onchange=upd;
  boxes.push({id:id,cb:cb,was:was});grid.appendChild(lab)});
 bar.appendChild(h('button',{class:'s',text:'Tout cocher',onclick:function(){boxes.forEach(function(b){b.cb.checked=true;b.cb.onchange()})}}));
 bar.appendChild(h('button',{class:'s',text:'Tout d\u00e9cocher',onclick:function(){boxes.forEach(function(b){b.cb.checked=false;b.cb.onchange()})}}));
 box.appendChild(bar);box.appendChild(grid);INIT[key]=boxes;return box}
function detail(){var d=$('detail');d.innerHTML='';INIT={};var s=effective(),pend=DATA.pend||[];
 d.appendChild(h('h2',{class:DATA.glow?'gn-glow':'',text:DATA.name}));
 d.appendChild(h('p',{class:'mut',text:'Cr\u00e9\u00e9 : '+fmt(DATA.created)+' - Derni\u00e8re sauvegarde : '+(DATA.save?fmt(DATA.save.ts):'aucune')}));
 d.appendChild(h('div',{class:'info',text:'Les modifications sont appliqu\u00e9es au prochain lancement du jeu du joueur, ou dans environ 20 secondes s\u2019il est d\u00e9j\u00e0 connect\u00e9. Les valeurs ci-dessous incluent les cadeaux d\u00e9j\u00e0 en attente.'}));
 if(!DATA.save)d.appendChild(h('div',{class:'warn',text:'Ce compte n\u2019a pas encore de sauvegarde en ligne (le joueur ne s\u2019est pas encore connect\u00e9 avec une partie).'}));
 d.appendChild(h('h3',{text:'Pseudo'}));
 var gcb=h('input',{type:'checkbox'}),gprev=h('span',{class:DATA.glow?'gn-glow':'',text:DATA.name,style:'font-size:18px'}),gmsg=h('span',{class:'mut',style:'font-size:13px'});gcb.checked=!!DATA.glow;
 gcb.onchange=function(){gcb.disabled=true;gmsg.textContent='Enregistrement...';call('/api/admin/setglow',{name:DATA.name,glow:gcb.checked}).then(function(j){DATA.glow=j.glow;gprev.className=j.glow?'gn-glow':'';gmsg.style.color='#3ecf6e';gmsg.textContent=j.glow?'Glow Mode activ\u00e9 (visible en jeu d\u2019ici ~20 s)':'Glow Mode d\u00e9sactiv\u00e9';gcb.disabled=false;
   for(var i=0;i<ACCS.length;i++)if(ACCS[i].name.toLowerCase()==CUR)ACCS[i].glow=j.glow;renderList('')}).catch(function(e){gcb.checked=!gcb.checked;gcb.disabled=false;alert(e.message)})};
 d.appendChild(h('div',{class:'glowbox'},[h('label',{class:'chk'},[gcb,document.createTextNode('Glow Mode (pseudo en surbrillance)')]),gprev,gmsg]));
 d.appendChild(h('h3',{text:'Valeurs (n\u00e9gatif = retirer)'}));var ng=h('div',{class:'grid'});INIT.num={};
 NUM.forEach(function(n){var inp=h('input',{type:'number',step:'1',placeholder:'0'});INIT.num[n[0]]=inp;
  var lab=h('label',{},[n[1],h('small',{text:'actuel : '+s[n[0]]+(n[0]=='ARL'?' / '+CAT.arMax:'')})]);ng.appendChild(h('div',{class:'num'},[lab,inp]))});d.appendChild(ng);
 d.appendChild(chkBlock('H\u00e9ros du Royaume',CAT.heroes,s.heroOwned,'h'));
 d.appendChild(chkBlock('Monstres Aether',CAT.monsters,s.aeOwned,'m'));
 d.appendChild(chkBlock('Sorts',CAT.spells,s.spOwned,'sp'));
 d.appendChild(chkBlock('\u00c9quipement - Royaume',CAT.equip,s.eqOwn.k,'ek'));
 d.appendChild(chkBlock('\u00c9quipement - Aether',CAT.equip,s.eqOwn.a,'ea'));
 var lv=[];for(var i=1;i<=CAT.levels;i++)lv.push([i,'Niveau '+i]);
 d.appendChild(chkBlock('Niveaux termin\u00e9s - Royaume',lv,s.lvDone,'lk'));
 d.appendChild(chkBlock('Niveaux termin\u00e9s - Aether',lv,s.lvDoneA,'la'));
 var msg=h('span',{id:'msg'});
 d.appendChild(h('div',{class:'sticky'},[h('button',{class:'p',text:'Envoyer les modifications',onclick:send}),msg]));
 d.appendChild(h('h3',{text:'Cadeaux en attente ('+pend.length+')'}));
 if(!pend.length)d.appendChild(h('p',{class:'mut',text:'Aucun.'}));
 pend.forEach(function(g){d.appendChild(h('div',{class:'pend'},[h('span',{text:fmt(g.at)+' : '+g.ops.map(opText).join(', ')}),h('button',{class:'s d',text:'Annuler',onclick:function(){call('/api/admin/cancel',{name:DATA.name,id:g.id}).then(function(){openAcc(DATA.name);loadList(false)}).catch(function(e){alert(e.message)})}})]))});
 d.appendChild(h('h3',{text:'Zone sensible'}));
 d.appendChild(h('div',{class:'bar'},[h('button',{class:'s',text:'Changer son mot de passe',onclick:function(){var p=prompt('Nouveau mot de passe pour '+DATA.name+' (4 caract\u00e8res minimum) :');if(!p)return;call('/api/admin/setpass',{name:DATA.name,pass:p}).then(function(){alert('Mot de passe chang\u00e9.')}).catch(function(e){alert(e.message)})}}),
  h('button',{class:'s d',text:'Supprimer le compte',onclick:function(){var p=prompt('Pour supprimer d\u00e9finitivement ce compte, tape son pseudo : '+DATA.name);if(!p)return;call('/api/admin/delete',{name:DATA.name,confirm:p}).then(function(){CUR=null;$('detail').innerHTML='Compte supprim\u00e9.';loadList(false)}).catch(function(e){alert(e.message)})}})]))}
function send(){var ops=[],k;
 for(k in INIT.num){var v=Math.round(Number(INIT.num[k].value));if(v)ops.push(['add',k,v])}
 var map={h:'heroOwned',m:'aeOwned',sp:'spOwned',ek:'eqK',ea:'eqA',lk:'lvDone',la:'lvDoneA'};
 for(k in map)(INIT[k]||[]).forEach(function(b){if(b.cb.checked!=b.was)ops.push([k=='lk'||k=='la'?'lv':'own',map[k],b.cb.checked?1:0,b.id])});
 if(!ops.length){$('msg').style.color='#ffd45a';$('msg').textContent='Rien \u00e0 envoyer : modifie une valeur ou coche/d\u00e9coche quelque chose.';return}
 if(!confirm('Envoyer ces modifications \u00e0 '+DATA.name+' ?\n\n'+ops.map(opText).join('\n')))return;
 call('/api/admin/give',{name:DATA.name,ops:ops}).then(function(){openAcc(DATA.name);loadList(false);setTimeout(function(){var m=$('msg');if(m){m.style.color='#3ecf6e';m.textContent='Envoy\u00e9 !'}},400)}).catch(function(e){alert(e.message)})}
(function(){try{var s=JSON.parse(sessionStorage.getItem('adm')||'null');if(s&&s.t){TOKEN=s.t;CAT=s.c;STORE=s.s;call('/api/admin/list').then(function(){main()}).catch(function(){login('')});return}}catch(e){}login('')})();
</script></body></html>
`;
function sendAdmin(res){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','X-Robots-Tag':'noindex',
  'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"});res.end(ADMIN_HTML)}

const server=http.createServer((req,res)=>{
  let u;try{u=decodeURIComponent((req.url||'/').split('?')[0])}catch(e){res.writeHead(400);return res.end('400')}
  if(u=='/api/status'){return json(res,200,{ok:1,store:store.kind})}
  if(u.startsWith('/api/admin/'))return adminApi(req,res,u);
  if(u.startsWith('/api/'))return api(req,res,u);
  if(u=='/admin'||u=='/admin/')return sendAdmin(res);
  if(u=='/turn.js'){res.writeHead(200,{'Content-Type':'text/javascript','Cache-Control':'no-store'});
    return res.end("window.AEG_RELAY=(location.protocol=='https:'?'wss://':'ws://')+location.host+'/ws';")}
  if(u=='/healthz'){res.writeHead(200);return res.end('ok')}
  if(u=='/')u='/index.html';
  const f=path.normalize(path.join(ROOT,u));
  if(!f.startsWith(ROOT)||/server\.js|package|[\\/]data[\\/]/.test(f)){res.writeHead(404);return res.end('404')}
  fs.readFile(f,(e,d)=>{if(e){res.writeHead(404);return res.end('404')}
    res.writeHead(200,{'Content-Type':MIME[path.extname(f)]||'application/octet-stream'});res.end(d)});
});
const wss=new WebSocketServer({server,path:'/ws',maxPayload:1<<20});
const rooms=new Map(); // code -> {host,guest}
function send(ws,o){if(ws&&ws.readyState==1)ws.send(JSON.stringify(o))}
wss.on('connection',ws=>{
  ws.alive=true;
  ws.on('message',raw=>{
    let m;try{m=JSON.parse(raw)}catch(e){return}
    if(m.k=='ka')return;
    if(m.k=='host'){
      const c=String(m.code||'').toUpperCase().slice(0,8);
      if(!c||rooms.has(c))return send(ws,{k:'err',m:'Code déjà utilisé, réessaie.'});
      rooms.set(c,{host:ws,guest:null});ws.room=c;ws.role='host';send(ws,{k:'ok'});
    }else if(m.k=='join'){
      const c=String(m.code||'').toUpperCase().slice(0,8),r=rooms.get(c);
      if(!r)return send(ws,{k:'err',m:'Room introuvable. Vérifie le code.'});
      if(r.guest)return send(ws,{k:'err',m:'Room pleine.'});
      r.guest=ws;ws.room=c;ws.role='guest';send(ws,{k:'ok'});send(r.host,{k:'peer'});
    }else if(m.k=='d'){
      const r=rooms.get(ws.room);if(!r)return;
      send(ws.role=='host'?r.guest:r.host,{k:'d',d:m.d});
    }
  });
  ws.on('close',()=>{
    const r=rooms.get(ws.room);if(!r)return;
    if(ws.role=='host'){send(r.guest,{k:'bye'});rooms.delete(ws.room);try{r.guest&&r.guest.close()}catch(e){}}
    else{r.guest=null;send(r.host,{k:'bye'})}
  });
});
server.listen(PORT,()=>console.log('Aethergard relay on',PORT));
