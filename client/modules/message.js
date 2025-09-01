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
let macKey = null // Uint8Array of shared secret
let macKeyB64 = null

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
  macKeyB64 = sessionStorage.getItem('quando-ws-key')
  if (token && macKeyB64) {
    // decode key once
    try {
      const raw = atob(macKeyB64)
      macKey = new Uint8Array(raw.length)
      for (let i=0;i<raw.length;i++) macKey[i] = raw.charCodeAt(i)
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
        if (env && env.type === 'secure' && env.payload && env.mac) {
          // verify MAC client-side
          if (macKey && _verifyMac(macKey, env.payload, env.mac)) {
            _handleWebSocketmessage({data: env.payload})
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

self._hmacBase64 = function(keyBytes, dataStr) {
  // Compute base64(HMAC-SHA256)
  // Uses CryptoJS loaded by client page; avoids WebCrypto secure-context limitation
  const keyWA = CryptoJS.lib.WordArray.create(keyBytes)
  const h = CryptoJS.HmacSHA256(dataStr, keyWA)
  return CryptoJS.enc.Base64.stringify(h)
}

function _verifyMac(keyBytes, dataStr, macB64) {
  try {
    const expected = self._hmacBase64(keyBytes, dataStr)
    return expected === macB64
  } catch (e) {
    return false
  }
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
    if (secureKeyed && macKey) {
      const envelope = {type:'secure', payload: plain, mac: self._hmacBase64(macKey, plain)}
      socket.send(JSON.stringify(envelope))
    } else {
      socket.send(plain)
    }
  }
}
