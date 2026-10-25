export async function onRequestPost({request,env}) {
  if (!env.SITE_PASSWORD || !env.SESSION_SECRET) {
    return Response.json({error:"Server not configured"},{status:503});
  }
  let body;
  try { body=await request.json(); }
  catch { return Response.json({ok:false},{status:400}); }

  if (typeof body.password!=="string" ||
      body.password!==env.SITE_PASSWORD) {
    return Response.json({ok:false},{status:401});
  }

  const expires=Math.floor(Date.now()/1000)+7*24*60*60;
  const data=String(expires);
  const key=await crypto.subtle.importKey(
    "raw",new TextEncoder().encode(env.SESSION_SECRET),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]
  );
  const signature=await crypto.subtle.sign(
    "HMAC",key,new TextEncoder().encode(data)
  );
  const token=btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");

  return new Response(JSON.stringify({ok:true}),{
    headers:{
      "Content-Type":"application/json",
      "Cache-Control":"no-store",
      "Set-Cookie":`love_session=${data}.${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`
    }
  });
}
