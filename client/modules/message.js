import * as destructor from "./destructor.js";

let quando = window['quando']
if (!quando) {
  alert('Fatal Error: message.js must be included after client.js')
} else if (!quando.ubit) {
  alert('Fatal Error: message.js must be included after ubit.js')
} else if (!quando.system) {
  alert('Fatal Error: message.js must be included after system.js')
}
let self = quando.message = {}

let io_protocol = "ws"
let port = window.location.port
let message_callback = {}
let message_callback_id = 0
let socket = false
let secureKeyed = false
let token = localStorage.getItem('quando-session-token')
let encKey = null // Uint8Array (32 bytes)
let macKey = null // Uint8Array (32 bytes)
let keyB64 = null

if (['wss:','https:'].includes(window.location.protocol)) {
  io_protocol += "s"
  if (port == 443) {
    port = ''
  }
} else if (port == 80) {
  port = ''
}
if (port != '') {
  port = ":" + port
}

function _connectWebSocket() {
  // Prefer secure application-layer channel if we have token AND key
  keyB64 = sessionStorage.getItem('quando-ws-key')
  if (token && keyB64) {
    // decode key once
    try {
      const raw = atob(keyB64)
      const ikm = new Uint8Array(raw.length)
      for (let i=0;i<raw.length;i++) ikm[i] = raw.charCodeAt(i)
      // Derive enc/mac keys via HKDF-SHA256 with sessionId salt
      const sessionId = (token.split('_')[1] || '')
      const out = hkdfExpand(ikm, utf8ToBytes(sessionId), utf8ToBytes('quando-ws-aead-v1'), 64)
      encKey = out.slice(0,32)
      macKey = out.slice(32,64)
    } catch(e) {
      console.warn('Failed to decode quando-ws-key, falling back to legacy WS')
    }

    let wss = new WebSocket(io_protocol + '://' + window.location.hostname + port + "/ws/secure")

    wss.onopen = () => {
      // authenticate connection
      wss.send(JSON.stringify({type:'auth', token}))
    }
    wss.onmessage = (e) => {
      try {
        const env = JSON.parse(e.data)
        if (env && env.type === 'secure' && env.nonce && env.ct && env.tag) {
          if (encKey && macKey) {
            const iv = b64ToBytes(env.nonce)
            const ct = b64ToBytes(env.ct)
            const expected = hmacBase64(macKey, bytesToConcat(iv, ct))
            if (expected !== env.tag) { console.warn('bad tag'); return }
            const pt = aesCtrXor(encKey, iv, ct)
            _handleWebSocketmessage({data: new TextDecoder().decode(pt)})
            secureKeyed = true
            socket = wss
            return
          } else {
            console.warn('Secure WS: bad MAC, dropped')
            return
          }
        }
      } catch (err) {
        // fallthrough to legacy parsing
      }
      _handleWebSocketmessage(e)
    }
    wss.onclose = () => {
      console.log("secure ws closed, fallback to legacy and retry")
      secureKeyed = false
      socket = false
      setTimeout(_connectWebSocket, 1000)
    }
    wss.onerror = () => {
      try { wss.close() } catch {}
    }
    socket = wss
    return
  }

  // Legacy unprotected websocket as fallback
  let ws = new WebSocket(io_protocol + '://' + window.location.hostname + port + "/ws/")

  ws.onclose = (e) => {
    console.log("reconnecting")
    socket = false
    setTimeout(_connectWebSocket, 1000)
  }
  ws.onerror = (e) => {
    console.log("error:"+e)
    ws.close(e)
  }
  ws.onmessage = _handleWebSocketmessage
  socket = ws
}
_connectWebSocket()

function _handleWebSocketmessage(e) {
  const message = JSON.parse(e.data)

  // console.log("message received: " + JSON.stringify(message))
  switch (message.type) {
    case 'deploy':
      let locStr = decodeURIComponent(window.location.href)
      if (locStr.endsWith(message.scriptname + ".html")) {
        window.location.reload(true) // nocache reload - probably not necessary
      }
      break
    case 'message':
      Object.values(message_callback).forEach(item => {
        if (item.message == message.message) {
          let val = message.val || 0 // 0 won't be sent so must fallback to 0
          if (message.txt !== undefined) {
            val = message.txt
          }
          item.callback(val)
        }
      })
      break
    case 'ubit':
      quando.ubit.handle_message(message)
      break
    case 'system':
      quando.system.handle_message(message)
      break
    case 'gamepad':
      quando.gamepad.server.handle_message(message)
      break
  }
}

function hmacBase64(keyBytes, data) {
  // Compute base64(HMAC-SHA256)
  // Uses CryptoJS loaded by client page; avoids WebCrypto secure-context limitation
  const keyWA = CryptoJS.lib.WordArray.create(keyBytes)
  const dataWA = (typeof data === 'string') ? CryptoJS.enc.Utf8.parse(data) : CryptoJS.lib.WordArray.create(data)
  const h = CryptoJS.HmacSHA256(dataWA, keyWA)
  return CryptoJS.enc.Base64.stringify(h)
}

function _verifyMac(keyBytes, dataStr, macB64) {
  try {
    const expected = hmacBase64(keyBytes, dataStr)
    return expected === macB64
  } catch (e) {
    return false
  }
}

function hkdfExpand(ikm, salt, info, length) {
  // Implement HKDF-Extract and Expand with HMAC-SHA256 using CryptoJS
  const prk = CryptoJS.HmacSHA256(CryptoJS.lib.WordArray.create(ikm), CryptoJS.lib.WordArray.create(salt))
  let t = CryptoJS.lib.WordArray.create()
  let okm = new Uint8Array(length)
  let pos = 0
  let counter = 1
  while (pos < length) {
    const data = CryptoJS.lib.WordArray.create(t.words.slice(0), t.sigBytes)
    const infoWA = CryptoJS.lib.WordArray.create(info)
    data.concat(infoWA)
    data.concat(CryptoJS.lib.WordArray.create([counter<<24], 1))
    t = CryptoJS.HmacSHA256(data, prk)
    const chunk = wordArrayToBytes(t)
    const take = Math.min(chunk.length, length - pos)
    okm.set(chunk.slice(0,take), pos)
    pos += take
    counter++
  }
  return okm
}

function wordArrayToBytes(wa){
  const bytes = []
  for (let i=0;i<wa.words.length;i++){
    const w = wa.words[i]
    bytes.push((w>>>24)&255,(w>>>16)&255,(w>>>8)&255,w&255)
  }
  return new Uint8Array(bytes.slice(0, wa.sigBytes))
}

function utf8ToBytes(str){ return new TextEncoder().encode(str) }
function b64ToBytes(b64){ const s=atob(b64); const a=new Uint8Array(s.length); for(let i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a }
function bytesToB64(b){ let s=''; for(let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s) }
function bytesToConcat(a,b){ const o=new Uint8Array(a.length+b.length); o.set(a,0); o.set(b,a.length); return o }
function aesCtrXor(key, iv, input){
  // Use CryptoJS AES-CTR via cipher params
  const keyWA = CryptoJS.lib.WordArray.create(key)
  const ivWA = CryptoJS.lib.WordArray.create(iv)
  const inpWA = CryptoJS.lib.WordArray.create(input)
  const enc = CryptoJS.AES.encrypt(inpWA, keyWA, { iv: ivWA, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding })
  // CryptoJS AES.encrypt returns WordArray ciphertext; we need raw bytes
  const ct = CryptoJS.enc.Base64.parse(enc.toString())
  return wordArrayToBytes(ct)
}

self.add_handler = (message, callback) => {
  let message_id = message_callback_id++
  message_callback[message_id] = {"message":message, "callback":callback}
  destructor.add( () => {
    delete message_callback[message_id]
  })
}

self.send = (message, val_txt, val) => {
  if (socket) {
    if (val === false) {
      val = 0.5
      if (val_txt == 'txt') {
        val = ''
      }
    }
    const plain = JSON.stringify({ 'type':'message', 'message':message, [val_txt]:val })
    if (secureKeyed && encKey && macKey) {
      const iv = crypto.getRandomValues(new Uint8Array(16))
      const ct = aesCtrXor(encKey, iv, new TextEncoder().encode(plain))
      const tag = hmacBase64(macKey, bytesToConcat(iv, ct))
      socket.send(JSON.stringify({ type:'secure', nonce: bytesToB64(iv), ct: bytesToB64(ct), tag }))
    } else {
      socket.send(plain)
    }
  }
}
