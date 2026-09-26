// MirageNet trap smoke test — verifies the honey-HTTP + honey-TCP trap pattern works.
// Uses ports 18081 (HTTP) and 12222 (TCP) to avoid clashing with the real mesh.
// Run: node tools/trap-smoke.mjs  → prints PASS lines or exits non-zero.
import http from 'node:http'
import net from 'node:net'

const HTTP_PORT = 18081
const TCP_PORT = 12222
const logs = []

function log(ev) {
  logs.push({ time: new Date().toISOString(), ...ev })
}

const FAKE_LOGIN = '<html><body><h2>Admin Login</h2><form method="POST" action="/login"></form></body></html>'

function startHttp() {
  return new Promise((resolve, reject) => {
    const srv = http.createServer((req, res) => {
      const ip = (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '')
      const ua = String(req.headers['user-agent'] ?? '')
      const method = req.method ?? 'GET'
      const p = (req.url ?? '/').split('?')[0]
      if (method === 'POST') {
        let body = ''
        req.on('data', (c) => (body += String(c)))
        req.on('end', () => {
          const m = body.match(/(?:^|&)(?:username|user|email|login)=([^&]*)/i)
          const username = m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : 'unknown'
          if (/password/i.test(body) && !body.includes('attempted')) {
            // ensure we never store the password itself
          }
          log({ kind: 'honey-http', ip, method, path: p, ua, username, attempted: true })
          res.writeHead(401, { 'Content-Type': 'text/html' })
          res.end(FAKE_LOGIN)
        })
        return
      }
      log({ kind: 'honey-http', ip, method, path: p, ua })
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end(FAKE_LOGIN)
    })
    srv.on('error', reject)
    srv.listen(HTTP_PORT, '127.0.0.1', () => resolve(srv))
  })
}

function startTcp() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer((sock) => {
      const ip = (sock.remoteAddress ?? 'unknown').replace(/^::ffff:/, '')
      try {
        sock.write('SSH-2.0-OpenSSH_9.2 MirageNet\r\n')
      } catch {}
      log({ kind: 'honey-tcp', ip, port: TCP_PORT })
      sock.on('data', (d) => log({ kind: 'banner-grab', ip, bytes: d.length, preview: d.toString('utf8').slice(0, 80) }))
      setTimeout(() => {
        try {
          sock.end()
        } catch {}
        try {
          sock.destroy()
        } catch {}
      }, 500)
    })
    srv.on('error', reject)
    srv.listen(TCP_PORT, '127.0.0.1', () => resolve(srv))
  })
}

const httpSrv = await startHttp()
const tcpSrv = await startTcp()

// 1) GET the fake login page
await new Promise((resolve, reject) => {
  http.get(`http://127.0.0.1:${HTTP_PORT}/`, { headers: { 'User-Agent': 'smoke-test/1.0' } }, (res) => {
    let b = ''
    res.on('data', (c) => (b += c))
    res.on('end', () => {
      if (res.statusCode !== 200 || !b.includes('Admin Login')) reject(new Error('fake login page mismatch'))
      else resolve()
    })
  }).on('error', reject)
})

// 2) POST fake credentials — username must be logged, password must NOT be stored
await new Promise((resolve, reject) => {
  const body = 'username=admin&password=supersecret123'
  const req = http.request(
    { host: '127.0.0.1', port: HTTP_PORT, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } },
    (res) => {
      res.resume()
      res.on('end', resolve)
    }
  )
  req.on('error', reject)
  req.end(body)
})

// 3) TCP banner grab
await new Promise((resolve, reject) => {
  const s = net.connect(TCP_PORT, '127.0.0.1', () => s.write('HELLO-SMOKE'))
  s.on('data', () => {})
  s.on('error', reject)
  setTimeout(() => {
    try {
      s.destroy()
    } catch {}
    resolve()
  }, 900)
})

await new Promise((r) => setTimeout(r, 400))

function assert(cond, label) {
  if (!cond) {
    console.error(`FAIL: ${label}`)
    console.error(JSON.stringify(logs, null, 2))
    process.exit(1)
  }
  console.log(`PASS: ${label}`)
}

assert(logs.some((l) => l.kind === 'honey-http' && l.method === 'GET' && l.path === '/'), 'honey HTTP logs GET / with ip+ua')
const post = logs.find((l) => l.kind === 'honey-http' && l.method === 'POST')
assert(!!post, 'honey HTTP logs POST /login')
assert(post.username === 'admin', 'posted username captured (admin)')
assert(!JSON.stringify(logs).includes('supersecret123'), 'posted password NEVER stored')
assert(logs.some((l) => l.kind === 'honey-tcp'), 'honey TCP logs connection with banner')
assert(logs.some((l) => l.kind === 'banner-grab' && l.preview.includes('HELLO-SMOKE')), 'banner-grab bytes captured')

console.log(`SMOKE PASS — ${logs.length} trap events logged`)
httpSrv.close()
tcpSrv.close()
process.exit(0)
