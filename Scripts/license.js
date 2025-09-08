// TrollOpen_2.3及以下版本均可使用该脚本激活使用，觉得不错请支持正版

// [task_local]
// event-interaction https://raw.githubusercontent.com/crctdd/QuantumultX/refs/heads/main/Scripts/license.js, tag=license, enabled=false
// ==============================================

// 在应用内点复制，将生成的udid手动替换掉“请输入udid”

const deviceId = "请输入udid";

if(!deviceId || deviceId.length<1){
  $notify("错误","未填写 UDID","");
  $done();
}

// 
function cryptoSHA256(msgBytes){
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  function ROTR(n,x){return (x>>>n)|(x<<(32-n));}
  function Σ0(x){return ROTR(2,x)^ROTR(13,x)^ROTR(22,x);}
  function Σ1(x){return ROTR(6,x)^ROTR(11,x)^ROTR(25,x);}
  function σ0(x){return ROTR(7,x)^ROTR(18,x)^(x>>>3);}
  function σ1(x){return ROTR(17,x)^ROTR(19,x)^(x>>>10);}
  function Ch(x,y,z){return (x&y)^(~x&z);}
  function Maj(x,y,z){return (x&y)^(x&z)^(y&z);}

  function sha256Block(msg){
    let H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    let l = msg.length*8;
    let withOne = new Uint8Array(msg.length+1); withOne.set(msg); withOne[msg.length]=0x80;
    let zeroPadLen=((56-(withOne.length%64))+64)%64;
    let padded=new Uint8Array(withOne.length+zeroPadLen+8); padded.set(withOne);
    let dv=new DataView(padded.buffer); dv.setUint32(padded.length-8,Math.floor(l/0x100000000)); dv.setUint32(padded.length-4,l>>>0);
    let W=new Uint32Array(64);

    for(let i=0;i<padded.length;i+=64){
      for(let t=0;t<16;t++){
        W[t]=(padded[i+t*4]<<24)|(padded[i+t*4+1]<<16)|(padded[i+t*4+2]<<8)|(padded[i+t*4+3]);
      }
      for(let t=16;t<64;t++){
        W[t]=(σ1(W[t-2])+W[t-7]+σ0(W[t-15])+W[t-16])>>>0;
      }
      let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for(let t=0;t<64;t++){
        let T1=(h+Σ1(e)+Ch(e,f,g)+K[t]+W[t])>>>0;
        let T2=(Σ0(a)+Maj(a,b,c))>>>0; h=g; g=f; f=e; e=(d+T1)>>>0; d=c; c=b; b=a; a=(T1+T2)>>>0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    let out = new Uint8Array(32);
    for(let i=0;i<8;i++){
      out[i*4]=(H[i]>>>24)&0xff;
      out[i*4+1]=(H[i]>>>16)&0xff;
      out[i*4+2]=(H[i]>>>8)&0xff;
      out[i*4+3]=H[i]&0xff;
    }
    return out;
  }

  return sha256Block(msgBytes);
}

function bytesToHex(bytes){return Array.from(bytes).map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();}

function generateLicense(deviceId){
  const salt = "hardsafe";
  const saltData = salt.slice(4)+salt.slice(0,4);
  let combined = deviceId + saltData;
  let md = cryptoSHA256(new TextEncoder().encode(combined));
  for(let i=0;i<41218;i++){
    md = cryptoSHA256(md);
  }
  let hex = bytesToHex(md);
  const positions=[8,13,18,23];
  for(let i=0;i<positions.length;i++){
    const pos=positions[i]+i;
    hex = hex.slice(0,pos) + "-" + hex.slice(pos);
  }
  return hex;
}

// =================== 生成激活码 ===================
const license = generateLicense(deviceId);

$notify("激活码生成成功", "", license);

console.log("激活码生成成功: " + license);

$done();
