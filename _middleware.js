async function validSession(request,secret) {
  const cookie=request.headers.get("Cookie")||"";
  const match=cookie.match(/(?:^|;\s*)love_session=(\d+)\.([A-Za-z0-9_-]+)/);
  if(!match)return false;

  const expires=Number(match[1]);
  if(!Number.isSafeInteger(expires)||expires<=Date.now()/1000)return false;

  try {
    const key=await crypto.subtle.importKey(
      "raw",new TextEncoder().encode(secret),
      {name:"HMAC",hash:"SHA-256"},false,["verify"]
    );
    let token=match[2].replace(/-/g,"+").replace(/_/g,"/");
    token+="=".repeat((4-token.length%4)%4);
    const signature=Uint8Array.from(atob(token),c=>c.charCodeAt(0));
    return await crypto.subtle.verify(
      "HMAC",key,signature,new TextEncoder().encode(match[1])
    );
  } catch { return false; }
}

export async function onRequest({request,env,next}) {
  const url=new URL(request.url);
  if(url.pathname==="/api/login")return next();

  if(url.pathname==="/"||url.pathname==="/index.html") {
    if(!env.SESSION_SECRET) {
      return new Response("الموقع لم يتم ضبط إعدادات الأمان فيه بعد.",{status:503});
    }
    if(!(await validSession(request,env.SESSION_SECRET))) {
      return Response.redirect(new URL("/login.html",url),302);
    }
  }
  return next();
}
