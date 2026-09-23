'use strict'
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawn}=require('node:child_process')
const {mnemonicToSeedSync,validateMnemonic}=require('@scure/bip39'),{wordlist}=require('@scure/bip39/wordlists/english')
const {base58check}=require('@scure/base'),{sha256}=require('@noble/hashes/sha256'),{secp256k1}=require('@noble/curves/secp256k1')
const {MwcOwnerRpc}=require('./owner-rpc.cjs')
const {freePort,waitFor,stopProcess}=require('../../../src/wallet-engines/sdk/process.cjs')
const {units,format,integer}=require('../../../src/wallet-engines/sdk/planner.cjs')
const validate=address=>{try{const b=base58check(sha256).decode(address);if(b.length!==35||b[0]!==1||b[1]!==69)return false;secp256k1.ProjectivePoint.fromHex(b.slice(2));return true}catch{return false}}
const identity=mnemonic=>{
  if(!validateMnemonic(mnemonic,wordlist))throw new Error('Invalid recovery phrase')
  const seed=Buffer.from(mnemonicToSeedSync(mnemonic))
  try{return{id:crypto.createHmac('sha256',seed).update('Altbase/mwc/profile/v1').digest('hex'),password:Buffer.from(crypto.hkdfSync('sha256',seed,Buffer.from('Altbase Wallet'),'mwc/storage-password/v1',32)).toString('hex')}}finally{seed.fill(0)}
}
const history=(address,rows,height,limit=50,offset=0)=>{
  const deltas=[],mempool=[],transactions=[]
  for(const row of rows.filter(r=>!['TxSentCancelled','TxReceivedCancelled','TxReverted'].includes(r.tx_type)).sort((a,b)=>Date.parse(b.creation_ts)-Date.parse(a.creation_ts)).slice(offset,offset+limit)){
    const txid=row.kernel_excess||row.tx_slate_id||`mwc-output-${row.id}`
    const delta=integer(row.amount_credited)-integer(row.amount_debited),timestamp=Math.floor(Date.parse(row.creation_ts)/1000)
    if(row.confirmed)deltas.push({txid,satoshis:delta.toString(),height:Number(row.output_height),timestamp})
    else mempool.push({txid,satoshis:delta.toString(),timestamp})
    const fee=integer(row.fee||'0'),value=format(delta<0n?-delta:delta,9)
    transactions.push({txid,time:timestamp,confirmations:row.confirmed?Math.max(1,height-Number(row.output_height)+1):0,fee:format(fee,9),vin:delta<0n?[{address,value}]:[{coinbase:row.tx_type==='ConfirmedCoinbase'?'reward':undefined}],vout:delta>0n?[{n:0,value,scriptPubKey:{address}}]:[]})
  }
  return{ok:true,address,txids:transactions.map(t=>t.txid),deltas,mempool,transactions}
}
const createRuntime=context=>{
  let active=null,generation=0
  const config=async(state,mqs)=>{
    const quote=value=>JSON.stringify(value)
    await fs.promises.mkdir(state.dir,{recursive:true,mode:0o700})
    const ownerSecret=path.join(state.dir,'.owner_api_secret')
    try{await fs.promises.writeFile(ownerSecret,crypto.randomBytes(32).toString('hex'),{flag:'wx',mode:0o600})}catch(e){if(e.code!=='EEXIST')throw e}
    // Only public settings and paths are persisted. The encrypted wallet is kept
    // at the same path on every unlock; scan results are never reset.
    await fs.promises.writeFile(path.join(state.dir,'mwc-wallet.toml'),`config_file_version = 2\n[wallet]\nchain_type = "Mainnet"\ndata_file_dir = ${quote(state.dir)}\napi_secret_path = ${quote(ownerSecret)}\ncheck_node_api_http_addr = ${quote(context.nodeUrl)}\nowner_api_listen_port = ${state.port}\nowner_api_include_foreign = false\nowner_api_include_mqs_listener = ${mqs}\n[mqs]\nmwcmqs_domain = "mqs.mwc.mw"\nmwcmqs_port = 443\n[logging]\nlog_to_stdout = false\nstdout_log_level = "Error"\nlog_to_file = false\nfile_log_level = "Error"\nlog_file_path = ${quote(path.join(state.dir,'wallet.log'))}\nlog_file_append = true\n`,{mode:0o600})
    return (await fs.promises.readFile(ownerSecret,'utf8')).trim()
  }
  const launch=async(state,mqs,password)=>{
    const secret=await config(state,mqs),args=['-t',state.dir,'-r',context.nodeUrl,'owner_api','--port',String(state.port)]
    if(state.cancelled)throw new Error('Wallet locked')
    const wrap=process.platform==='win32'&&mqs
    state.child=(context.spawn||spawn)(wrap?context.consoleHelper:context.binary,wrap?[context.binary,...args]:args,{cwd:state.dir,stdio:['pipe','ignore','ignore'],shell:false,windowsHide:true,env:{...process.env,TOKIO_WORKER_THREADS:'1',RAYON_NUM_THREADS:'1'}})
    state.child.on('error',error=>{state.child._altbaseSpawnError=error.code||'spawn failed'});state.child.stdin.on('error',()=>{})
    state.child.stdin.end(mqs?password+'\n':undefined)
    state.rpc=(context.createOwnerRpc?context.createOwnerRpc(state.port,secret):new MwcOwnerRpc(state.port,secret))
    await waitFor(()=>state.rpc.initialize(),state.child,mqs?90000:15000)
    state.token=await state.rpc.call('open_wallet',{name:null,password})
  }
  const prepare=async(state,mnemonic,password)=>{
    state.port=await freePort()
    // Bootstrap through the encrypted Owner API, including on first restore.
    const secret=await config(state,false)
    if(state.cancelled)throw new Error('Wallet locked')
    state.child=(context.spawn||spawn)(context.binary,['-t',state.dir,'-r',context.nodeUrl,'owner_api','--port',String(state.port)],{cwd:state.dir,stdio:'ignore',windowsHide:true,shell:false,env:{...process.env,TOKIO_WORKER_THREADS:'1',RAYON_NUM_THREADS:'1'}})
    state.child.on('error',error=>{state.child._altbaseSpawnError=error.code||'spawn failed'});state.rpc=(context.createOwnerRpc?context.createOwnerRpc(state.port,secret):new MwcOwnerRpc(state.port,secret))
    await waitFor(()=>state.rpc.initialize(),state.child,15000)
    if(!fs.existsSync(path.join(state.dir,'wallet_data','wallet.seed')))await state.rpc.call('create_wallet',{name:null,mnemonic,mnemonic_length:mnemonic.split(' ').length===24?32:16,password})
    state.token=await state.rpc.call('open_wallet',{name:null,password})
    const address=await state.rpc.call('get_mqs_address',{token:state.token})
    if(!validate(address.public_key))throw new Error('Reference wallet returned an invalid MWC address')
    state.address=address.public_key
    state.starting=(async()=>{
      state.rpc.close();await stopProcess(state.child)
      if(state.cancelled)return
      await launch(state,true,password)
      state.ready=true
      await rescan(state)
    })().catch(()=>{state.error='Local MWC wallet or MQS listener failed to start; reopen the wallet to retry'})
    return{address:state.address}
  }
  const rescan=async state=>{
    if(state.scanning||state.cancelled)return
    const marker=path.join(state.dir,'scan-complete.json')
    if(fs.existsSync(marker)){state.scanned=true;return}
    state.scanning=true;state.scanError=null
    try{
      await state.rpc.call('scan',{token:state.token,start_height:1,delete_unconfirmed:false},1800000)
      if(state.cancelled)return
      const [fresh,summary]=await state.rpc.call('retrieve_summary_info',{token:state.token,refresh_from_node:true,minimum_confirmations:1})
      if(!fresh||Number(summary.last_confirmed_height)<1)throw new Error('MWC scan did not reach a verified node height')
      await fs.promises.writeFile(marker,JSON.stringify({completedAt:new Date().toISOString(),height:summary.last_confirmed_height}),{mode:0o600})
      state.scanned=true
    }catch(error){state.scanError='MWC recovery scan could not finish; reopen the wallet to retry. Existing scan data has been preserved';context.onDiagnostic?.({event:'scan-failed',message:error.message})}finally{state.scanning=false}
  }
  const derive=async({mnemonic})=>{
    const {id,password}=identity(mnemonic)
    if(active?.id===id)return active.preparing
    const revision=++generation
    await stopActive()
    if(revision!==generation)throw new Error('Wallet was locked during restoration')
    const state={id,dir:path.join(context.baseDir,id),ready:false,scanned:false};active=state
    state.preparing=prepare(state,mnemonic,password).catch(()=>{state.error='Local MWC wallet could not be opened';throw new Error(state.error)})
    return state.preparing
  }
  const current=address=>{if(!active||active.address!==address)throw new Error('Unlock this MWC wallet before checking its balance');if(active.error)throw new Error(active.error);if(active.scanError)throw new Error(active.scanError);return active}
  const snapshot=async({address,network,includeHistory=true,historyLimit=50,historyOffset=0})=>{
    const state=current(address),target=network?.blocks
    if(!Number.isSafeInteger(target)||target<1)throw new Error('Current MWC node height is unavailable')
    if(!state.ready||!state.scanned||state.scanning){
      if(state.ready){
        const messages=await state.rpc.call('get_updater_messages',{count:100}).catch(()=>[])
        for(const message of messages){
          if(Array.isArray(message.Scanning))state.scanPercent=Math.max(state.scanPercent||0,message.Scanning[2])
          context.onDiagnostic?.({event:'scan-message',kind:Object.keys(message)[0],percent:Array.isArray(message.Scanning)?message.Scanning[2]:undefined})
        }
      }
      return{syncing:true,height:0,targetHeight:target,scanPercent:state.scanPercent}
    }
    const [fresh,summary]=await state.rpc.call('retrieve_summary_info',{token:state.token,refresh_from_node:true,minimum_confirmations:1})
    if(!fresh)throw new Error('MWC node did not refresh the local balance')
    const height=Number(summary.last_confirmed_height)
    if(height<target)return{syncing:true,height,targetHeight:target}
    const balance={balance:integer(summary.total).toString(),balance_spendable:integer(summary.amount_currently_spendable).toString(),received:integer(summary.total).toString(),immature:integer(summary.amount_immature).toString(),pendingIncoming:integer(summary.amount_awaiting_confirmation).toString()}
    const rows=includeHistory?(await state.rpc.call('retrieve_txs',{token:state.token,refresh_from_node:false,tx_id:null,tx_slate_id:null,show_last_four_days:false}))[1]:[]
    return{syncing:false,height,targetHeight:target,balance,history:includeHistory?history(address,rows,height,historyLimit,historyOffset):undefined}
  }
  const plan=async params=>{
    if(!validate(params.toAddress))throw new Error('Enter a mainnet MWC MQS address; the recipient wallet must be online')
    const state=current(params.fromAddress),snap=await snapshot({address:params.fromAddress,network:await context.getNetwork(),includeHistory:false})
    if(snap.syncing)throw new Error('Wait for the MWC recovery scan to finish')
    const available=integer(snap.balance.balance_spendable),amount=params.sendMax?available:units(params.amountCoin,9)
    if(amount<=0n)throw new Error('No confirmed spendable MWC balance')
    const requestedFee=params.feeCoin?units(params.feeCoin,9):null
    if(requestedFee!==null&&(requestedFee<0n||requestedFee>BigInt(Number.MAX_SAFE_INTEGER)))throw new Error('Unsafe MWC fee')
    const args={amount:amount.toString(),amount_includes_fee:!!params.sendMax,minimum_confirmations:1,max_outputs:500,num_change_outputs:1,selection_strategy_is_use_all:!!params.sendMax,estimate_only:true,send_args:null,min_fee:requestedFee===null?null:Number(requestedFee)}
    const estimate=await state.rpc.call('init_send_tx',{token:state.token,args})
    const fee=integer(estimate.fee),net=params.sendMax?amount-fee:amount
    if(net<=0n||net+fee>available)throw new Error('Insufficient synchronized MWC balance')
    if(params.maxFeeCoin&&fee>units(params.maxFeeCoin,9))throw new Error('Fee changed; review the current fee')
    if(fee>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Unsafe MWC fee')
    return{amountCoin:format(net,9),feeCoin:format(fee,9),feeSatoshis:Number(fee)}
  }
  const send=async params=>{
    const approved=await plan(params),state=current(params.fromAddress)
    if(params.sendMax&&units(params.amountCoin,9)!==units(approved.amountCoin,9))throw new Error('MAX changed; review the current amount')
    const slate=await state.rpc.call('init_send_tx',{token:state.token,args:{amount:units(approved.amountCoin,9).toString(),amount_includes_fee:false,minimum_confirmations:1,max_outputs:500,num_change_outputs:1,selection_strategy_is_use_all:!!params.sendMax,estimate_only:false,min_fee:approved.feeSatoshis,send_args:{method:'mwcmqs',dest:params.toAddress,finalize:true,post_tx:false,fluff:false}}},180000)
    if(integer(slate.fee)!==BigInt(approved.feeSatoshis)||integer(slate.amount)!==units(approved.amountCoin,9))throw new Error('MWC fee or amount changed; transaction was not broadcast')
    const kernel=slate.tx?.body?.kernels?.[0]?.excess
    if(!kernel)throw new Error('MWC wallet returned no finalized transaction kernel')
    await state.rpc.call('post_tx',{token:state.token,tx:slate.tx,fluff:false})
    return{txid:kernel,...approved}
  }
  const stopActive=async()=>{const previous=active;active=null;if(previous){previous.cancelled=true;await stopProcess(previous.child);previous.rpc?.close()}}
  const close=async()=>{++generation;await stopActive()}
  return{derive,validate:async({address})=>({valid:validate(address)}),snapshot,status:params=>snapshot({...params,address:active?.address,includeHistory:false}),plan,send,export:async({mnemonic})=>{identity(mnemonic);return{secret:mnemonic}},close}
}
module.exports={createRuntime,validate,history,identity}
