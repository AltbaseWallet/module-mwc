'use strict'
const crypto=require('node:crypto'),http=require('node:http')
const {secp256k1}=require('@noble/curves/secp256k1')
const postJson=(url,body,authorization,timeout)=>new Promise((resolve,reject)=>{
  const data=Buffer.from(JSON.stringify(body))
  const request=http.request(url,{method:'POST',headers:{'Content-Type':'application/json',Authorization:authorization,'Content-Length':data.length}},response=>{
    const chunks=[];let size=0
    response.on('data',chunk=>{size+=chunk.length;if(size>64000000){response.destroy(new Error('Local MWC response exceeded its limit'));return}chunks.push(chunk)})
    response.on('error',reject)
    response.on('end',()=>{try{if(response.statusCode!==200)throw new Error('Local MWC wallet HTTP '+response.statusCode);resolve(JSON.parse(Buffer.concat(chunks)))}catch(error){reject(error)}})
  })
  request.setTimeout(timeout,()=>request.destroy(new Error('Local MWC RPC timed out')))
  request.on('error',reject);request.end(data)
})
// The reference wallet's Owner API v3 uses secp256k1 ECDH followed by AES-GCM.
// This client is exclusively for a private loopback process, never a backend.
class MwcOwnerRpc{
  constructor(port,password){this.url=`http://127.0.0.1:${port}/v3/owner`;this.auth='Basic '+Buffer.from('mwc:'+password).toString('base64');this.id=0;this.key=null}
  async raw(method,params,timeout=60000){
    // Native HTTP avoids fetch's fixed 300-second response-header deadline
    // during a full recovery scan, while retaining an explicit upper bound.
    const body=await postJson(this.url,{jsonrpc:'2.0',id:++this.id,method,params},this.auth,timeout)
    if(body.error)throw new Error(`Local MWC ${method} failed (${body.error.code})`)
    return body.result??body
  }
  unwrap(result,method){
    if(result && Object.hasOwn(result,'Err')){const kind=result.Err&&typeof result.Err==='object'?Object.keys(result.Err).join(','):'reference error';throw new Error(`Local MWC ${method} failed (${kind})`)}
    return result && Object.hasOwn(result,'Ok')?result.Ok:result
  }
  async initialize(){
    // Electron's BoringSSL omits secp256k1 ECDH. Use the same curve through
    // the pinned curve library and keep the reference 32-byte X secret.
    const privateKey=secp256k1.utils.randomPrivateKey()
    try {
      const result=this.unwrap(await this.raw('init_secure_api',{ecdh_pubkey:Buffer.from(secp256k1.getPublicKey(privateKey,true)).toString('hex')}),'secure API initialization')
      const publicKey=typeof result==='string'?result:result.ecdh_pubkey
      this.key=Buffer.from(secp256k1.getSharedSecret(privateKey,publicKey,true).slice(1))
    } finally { privateKey.fill(0) }
  }
  async call(method,params,timeout){
    if(!this.key)await this.initialize()
    const nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',this.key,nonce)
    const plain=Buffer.from(JSON.stringify({jsonrpc:'2.0',id:++this.id,method,params}))
    const body_enc=Buffer.concat([cipher.update(plain),cipher.final(),cipher.getAuthTag()]).toString('base64');plain.fill(0)
    const result=this.unwrap(await this.raw('encrypted_request_v3',{nonce:nonce.toString('hex'),body_enc},timeout),'encrypted request')
    const encrypted=Buffer.from(result.body_enc,'base64'),decipher=crypto.createDecipheriv('aes-256-gcm',this.key,Buffer.from(result.nonce,'hex'))
    decipher.setAuthTag(encrypted.subarray(-16))
    const decoded=Buffer.concat([decipher.update(encrypted.subarray(0,-16)),decipher.final()])
    try{const response=JSON.parse(decoded);if(response.error)throw new Error(`Local MWC ${method} failed (${response.error.code})`);return this.unwrap(response.result,method)}finally{decoded.fill(0)}
  }
  close(){this.key?.fill(0);this.key=null;this.auth=''}
}
module.exports={MwcOwnerRpc}
