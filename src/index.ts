/**
 * GenosSIG — GenosDB signalling relay.
 *
 * Cloudflare Worker + ONE Durable Object. Nostr-shaped, GenosRTC-only:
 * peers exchange WebRTC SDP/ICE through here and then talk directly.
 * Nothing is stored — no database, no history, no replay. An event is
 * verified, fanned out to matching subscribers, and forgotten.
 *
 * Accepted traffic is structurally GenosRTC's and nothing else:
 *   EVENT  kind 20000-29999 (ephemeral), exactly one ["x", topic] tag,
 *          kind === strToNum(topic) + 20000 (the client derives the kind
 *          from the topic, so coherence is a signature no generic Nostr
 *          client produces), schnorr-verified with id recomputation.
 *   REQ    exactly {kinds:[k], since?, "#x":[topic]} with the same
 *          coherence — anything else is CLOSED.
 *   CLOSE  drops the subscription.
 * Replies: OK / EOSE / CLOSED / NOTICE. Never a PoW demand (GenosRTC
 * blacklists any relay whose NOTICE/OK mentions proof-of-work).
 */

import { schnorr } from '@noble/curves/secp256k1.js'

// ---------------------------------------------------------------------------
// Tuning
// ---------------------------------------------------------------------------

const KIND_FLOOR = 20000 // NIP-01 ephemeral range: relays never store these
const KIND_CEIL = 30000

// GenosRTC topics are sha1 digests rendered byte-by-byte in base36.
const TOPIC_RE = /^[0-9a-z]{20,40}$/

const MAX_MESSAGE_CHARS = 16384 // whole frame; an SDP with TURN candidates runs 2-5 KB
const MAX_SUB_ID_CHARS = 64 // GenosRTC uses 64
const MAX_SUBS_PER_SOCKET = 8 // GenosRTC opens 2 (root + self)
const MAX_SUBS_PER_TOPIC = 256 // "max peers per room" as seen from the relay
const MAX_SOCKETS_PER_IP = 32
const SINCE_SLACK_S = 60 // subscriber clock vs publisher clock

// Per-socket burst budget. A WebRTC negotiation publishes ~25 events in a
// few seconds, so the limit must absorb bursts — and never key on pubkey,
// which is a throwaway per session.
const BUCKET_CAPACITY = 60
const BUCKET_REFILL_PER_S = 6

// Protocol violations before the socket is evicted. A GenosRTC client never
// accrues one (being rate-limited is not a violation); a generic Nostr
// client hits the cap within its first seconds of trying.
const MAX_STRIKES = 10

// One object for the whole relay: it is chosen at upgrade time, before any
// REQ names a topic, so sharding cannot route by room — peers must all land
// in the same place to meet.
const DO_NAME = 'sig-weur-v2'
const DO_HINT: DurableObjectLocationHint = 'weur'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NostrEvent {
  id: string
  pubkey: string
  created_at: number
  kind: number
  tags: string[][]
  content: string
  sig: string
}

interface SubEntry {
  topic: string
  since: number
}

/** Everything a socket needs survives hibernation inside its attachment. */
interface Attachment {
  ip: string
  /** City-level [lat, lon, country], rounded to ~11 km — display only. */
  geo?: [number, number, string]
  subs: [string, SubEntry][]
}

export interface Env {
  RELAY_WEBSOCKET: DurableObjectNamespace
}

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/

/** Mirror of GenosRTC's topicToKind: charCode sum % 10000, into the ephemeral range. */
const topicToKind = (topic: string): number => {
  let sum = 0
  for (let i = 0; i < topic.length; i++) sum += topic.charCodeAt(i)
  return (sum % 10000) + KIND_FLOOR
}

const hexToBytes = (hex: string): Uint8Array => {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  return bytes
}

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

/** Recompute the NIP-01 event id and verify its schnorr signature. */
const verifyEvent = async (ev: NostrEvent): Promise<boolean> => {
  try {
    const preimage = new TextEncoder().encode(
      JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])
    )
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage))
    if (bytesToHex(digest) !== ev.id) return false
    return schnorr.verify(hexToBytes(ev.sig), digest, hexToBytes(ev.pubkey))
  } catch {
    return false
  }
}

/**
 * Structural gate: returns the event's topic when it is GenosRTC traffic,
 * or a refusal reason string. Cheap checks only — the schnorr verification
 * runs after this passes.
 */
const gateEvent = (ev: unknown): { topic: string } | { reason: string } => {
  if (typeof ev !== 'object' || ev === null || Array.isArray(ev)) return { reason: 'invalid: event object required' }
  const e = ev as NostrEvent
  if (
    typeof e.id !== 'string' || !HEX_64.test(e.id) ||
    typeof e.pubkey !== 'string' || !HEX_64.test(e.pubkey) ||
    typeof e.sig !== 'string' || !HEX_128.test(e.sig) ||
    typeof e.content !== 'string' ||
    !Number.isInteger(e.created_at) || e.created_at <= 0 || e.created_at >= 4_000_000_000 ||
    !Number.isInteger(e.kind) || !Array.isArray(e.tags)
  ) {
    return { reason: 'invalid: missing or malformed fields' }
  }
  if (e.kind < KIND_FLOOR || e.kind >= KIND_CEIL) return { reason: 'blocked: ephemeral kinds only' }
  const tag = e.tags.length === 1 ? e.tags[0] : null
  if (!tag || !Array.isArray(tag) || tag.length !== 2 || tag[0] !== 'x' || typeof tag[1] !== 'string') {
    return { reason: 'blocked: not GenosRTC traffic' }
  }
  const topic = tag[1]
  if (!TOPIC_RE.test(topic) || e.kind !== topicToKind(topic)) {
    return { reason: 'blocked: not GenosRTC traffic' }
  }
  return { topic }
}

/** Same idea for a REQ filter: closed-form or refused. */
const gateFilter = (filter: unknown): SubEntry | { reason: string } => {
  if (typeof filter !== 'object' || filter === null || Array.isArray(filter)) return { reason: 'unsupported: filter object required' }
  const f = filter as Record<string, unknown>
  for (const key of Object.keys(f)) {
    if (key !== 'kinds' && key !== 'since' && key !== '#x') return { reason: 'unsupported: GenosRTC filters only' }
  }
  const kinds = f['kinds']
  const topics = f['#x']
  if (!Array.isArray(kinds) || kinds.length !== 1 || !Number.isInteger(kinds[0])) return { reason: 'unsupported: one kind required' }
  if (!Array.isArray(topics) || topics.length !== 1 || typeof topics[0] !== 'string') return { reason: 'unsupported: one #x topic required' }
  const topic = topics[0]
  if (!TOPIC_RE.test(topic) || kinds[0] !== topicToKind(topic)) return { reason: 'unsupported: GenosRTC filters only' }
  let since = 0
  if (f['since'] !== undefined) {
    if (typeof f['since'] !== 'number' || !Number.isFinite(f['since']) || f['since'] < 0) return { reason: 'unsupported: bad since' }
    since = f['since']
  }
  return { topic, since }
}

// ---------------------------------------------------------------------------
// Durable Object — every session lives here, so local fan-out is total fan-out
// ---------------------------------------------------------------------------

interface Stats {
  accepted: number
  delivered: number
  dropped: number
}

export class RelayWebSocket {
  private state: DurableObjectState
  // Lifetime counters. Hibernation wipes memory while sockets stay open, so
  // they are hydrated from storage on wake and flushed lazily (every N bumps,
  // on session close and on /health) — never awaited in the hot path.
  private stats: Stats = { accepted: 0, delivered: 0, dropped: 0 }
  private unflushed = 0
  private flushTimer: ReturnType<typeof setTimeout> | undefined
  // Caches over hibernatable sockets; repopulated lazily from attachments.
  private attCache = new WeakMap<WebSocket, Attachment>()
  private buckets = new WeakMap<WebSocket, { tokens: number; last: number }>()
  private strikes = new WeakMap<WebSocket, number>()

  constructor(state: DurableObjectState) {
    this.state = state
    state.blockConcurrencyWhile(async () => {
      const saved = await state.storage.get<Stats>('stats')
      if (saved) this.stats = saved
    })
  }

  private bump(kind: keyof Stats): void {
    this.stats[kind]++
    if (++this.unflushed >= 50) this.scheduleFlush()
  }

  // Deferred to its own task: a pending storage write holds outgoing
  // messages behind the output gate, so flushing inline would tax the
  // fan-out of whichever event crosses the threshold.
  private scheduleFlush(): void {
    this.flushTimer ??= setTimeout(() => this.flush(), 0)
  }

  private flush(): void {
    if (this.flushTimer !== undefined) {
      clearTimeout(this.flushTimer)
      this.flushTimer = undefined
    }
    if (!this.unflushed) return
    this.unflushed = 0
    this.state.storage.put('stats', this.stats).catch(() => {})
  }

  private getAtt(ws: WebSocket): Attachment | null {
    let att = this.attCache.get(ws)
    if (!att) {
      att = (ws.deserializeAttachment() as Attachment | null) ?? undefined
      if (att) this.attCache.set(ws, att)
    }
    return att ?? null
  }

  private setAtt(ws: WebSocket, att: Attachment): void {
    ws.serializeAttachment(att)
    this.attCache.set(ws, att)
  }

  private allowBurst(ws: WebSocket): boolean {
    const now = Date.now()
    let b = this.buckets.get(ws)
    if (!b) {
      b = { tokens: BUCKET_CAPACITY, last: now }
      this.buckets.set(ws, b)
    }
    b.tokens = Math.min(BUCKET_CAPACITY, b.tokens + ((now - b.last) / 1000) * BUCKET_REFILL_PER_S)
    b.last = now
    if (b.tokens < 1) return false
    b.tokens -= 1
    return true
  }

  private send(ws: WebSocket, payload: unknown[]): void {
    try {
      ws.send(JSON.stringify(payload))
    } catch {
      // Socket already gone; hibernation cleanup will reap it.
    }
  }

  /** Protocol violation: count it, answer it, evict repeat offenders. */
  private refuse(ws: WebSocket, payload: unknown[]): void {
    this.bump('dropped')
    const n = (this.strikes.get(ws) ?? 0) + 1
    this.strikes.set(ws, n)
    this.send(ws, payload)
    if (n >= MAX_STRIKES) {
      try {
        ws.close(1008, 'not GenosRTC traffic')
      } catch {
        // Already closed.
      }
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    if (url.pathname === '/health') {
      this.flush()
      // Locations aggregated by rounded position — counts only, never IPs or
      // ids. Rooms = topics shared by ≥2 sockets: every peer of a room
      // subscribes to the same rootTopic, while selfTopics are per-peer, so
      // a shared topic is a room with signalling actually in flight.
      const locations = new Map<string, { lat: number; lon: number; cc: string; n: number }>()
      const topicSubs = new Map<string, number>()
      for (const peer of this.state.getWebSockets()) {
        const att = this.getAtt(peer)
        if (!att) continue
        for (const [, sub] of att.subs) {
          topicSubs.set(sub.topic, (topicSubs.get(sub.topic) ?? 0) + 1)
        }
        const g = att.geo
        if (!g) continue
        const found = locations.get(`${g[0]},${g[1]}`)
        if (found) found.n++
        else locations.set(`${g[0]},${g[1]}`, { lat: g[0], lon: g[1], cc: g[2], n: 1 })
      }
      let rooms = 0
      for (const n of topicSubs.values()) if (n >= 2) rooms++
      return Response.json({
        relay: 'GenosSIG',
        service: 'GenosDB signalling',
        connections: this.state.getWebSockets().length,
        rooms,
        ...this.stats,
        locations: [...locations.values()],
      })
    }

    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 })
    }

    const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown'
    let sameIp = 0
    for (const peer of this.state.getWebSockets()) {
      if (this.getAtt(peer)?.ip === ip && ++sameIp >= MAX_SOCKETS_PER_IP) {
        return new Response('Too many connections', { status: 429 })
      }
    }

    // Set by the Worker from request.cf; any client-supplied value was replaced.
    let geo: Attachment['geo']
    const geoParam = url.searchParams.get('geo')
    if (geoParam) {
      const [la, lo, cc] = geoParam.split(',')
      const lat = Number(la)
      const lon = Number(lo)
      if (Number.isFinite(lat) && Number.isFinite(lon)) geo = [lat, lon, cc ?? '']
    }

    const pair = new WebSocketPair()
    const client = pair[0]
    const server = pair[1]

    this.setAtt(server, { ip, geo, subs: [] })
    // Hibernatable accept is mandatory, not a choice: webSocketMessage() and
    // state.getWebSockets() only ever fire for sockets accepted this way.
    // A plain server.accept() deploys fine and then nothing arrives.
    this.state.acceptWebSocket(server)

    // Nothing is awaited before the 101: the browser does not consider the
    // socket open until this response arrives.
    return new Response(null, { status: 101, webSocket: client })
  }

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    if (typeof raw !== 'string' || raw.length > MAX_MESSAGE_CHARS) {
      return this.refuse(ws, ['NOTICE', 'invalid: oversized or binary frame'])
    }
    let msg: unknown
    try {
      msg = JSON.parse(raw)
    } catch {
      return this.refuse(ws, ['NOTICE', 'invalid: not JSON'])
    }
    if (!Array.isArray(msg)) {
      return this.refuse(ws, ['NOTICE', 'invalid: expected array'])
    }

    const [type] = msg
    if (type === 'EVENT') return this.handleEvent(ws, msg[1])
    if (type === 'REQ') return this.handleReq(ws, msg)
    if (type === 'CLOSE') return this.handleClose(ws, msg[1])
    this.refuse(ws, ['NOTICE', 'unsupported: GenosRTC signalling only'])
  }

  private async handleEvent(ws: WebSocket, ev: unknown): Promise<void> {
    const gate = gateEvent(ev)
    if ('reason' in gate) {
      const id = typeof (ev as NostrEvent)?.id === 'string' ? (ev as NostrEvent).id : ''
      return this.refuse(ws, ['OK', id, false, gate.reason])
    }
    const event = ev as NostrEvent
    if (!this.allowBurst(ws)) {
      // Legitimate traffic being throttled — never a strike.
      this.bump('dropped')
      return this.send(ws, ['OK', event.id, false, 'rate-limited: slow down'])
    }
    if (!(await verifyEvent(event))) {
      return this.refuse(ws, ['OK', event.id, false, 'invalid: bad signature'])
    }

    this.bump('accepted')
    this.send(ws, ['OK', event.id, true, ''])

    // Ephemeral fan-out: serialize the event once, then one delivery per
    // socket on its first matching subscription (GenosRTC's root/self
    // subscriptions target disjoint topics, so at most one matches anyway).
    // Nothing is stored.
    const eventJson = JSON.stringify(event)
    for (const peer of this.state.getWebSockets()) {
      const att = this.getAtt(peer)
      if (!att) continue
      for (const [id, sub] of att.subs) {
        if (sub.topic === gate.topic && event.created_at >= sub.since - SINCE_SLACK_S) {
          try {
            peer.send(`["EVENT",${JSON.stringify(id)},${eventJson}]`)
          } catch {
            // Socket already gone; hibernation cleanup will reap it.
          }
          this.bump('delivered')
          break
        }
      }
    }
  }

  private handleReq(ws: WebSocket, msg: unknown[]): void {
    const subId = msg[1]
    if (typeof subId !== 'string' || !subId.length || subId.length > MAX_SUB_ID_CHARS) {
      return this.refuse(ws, ['NOTICE', 'invalid: bad subscription id'])
    }
    if (msg.length !== 3) {
      return this.refuse(ws, ['CLOSED', subId, 'unsupported: exactly one filter required'])
    }
    const gate = gateFilter(msg[2])
    if ('reason' in gate) {
      return this.refuse(ws, ['CLOSED', subId, gate.reason])
    }

    const att = this.getAtt(ws)
    if (!att) return
    const existing = att.subs.findIndex(([id]) => id === subId)

    if (existing === -1) {
      if (att.subs.length >= MAX_SUBS_PER_SOCKET) {
        return this.refuse(ws, ['CLOSED', subId, 'blocked: too many subscriptions'])
      }
      // Room occupancy across all sockets, counted on demand (REQ is rare).
      let roomSubs = 0
      for (const peer of this.state.getWebSockets()) {
        const peerAtt = this.getAtt(peer)
        if (peerAtt?.subs.some(([, s]) => s.topic === gate.topic) && ++roomSubs >= MAX_SUBS_PER_TOPIC) {
          this.bump('dropped')
          return this.send(ws, ['CLOSED', subId, 'blocked: room is full'])
        }
      }
      att.subs.push([subId, gate])
    } else {
      // Re-sent REQ under the same id replaces the subscription — GenosRTC
      // relies on this when a socket reopens after a network drop.
      att.subs[existing] = [subId, gate]
    }
    this.setAtt(ws, att)

    // No history to send: ephemeral-only, EOSE is immediate.
    this.send(ws, ['EOSE', subId])
  }

  private handleClose(ws: WebSocket, subId: unknown): void {
    if (typeof subId !== 'string') return
    const att = this.getAtt(ws)
    if (!att) return
    const remaining = att.subs.filter(([id]) => id !== subId)
    if (remaining.length !== att.subs.length) this.setAtt(ws, { ...att, subs: remaining })
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    this.flush()
    try {
      ws.close(code, 'closing')
    } catch {
      // Already closed.
    }
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    try {
      ws.close(1011, 'error')
    } catch {
      // Already closed.
    }
  }
}

// ---------------------------------------------------------------------------
// Worker — upgrade to the one DO, GenosDB front page, health
// ---------------------------------------------------------------------------

const FAVICON =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ccircle cx='8' cy='8' r='6' fill='%234c8dff'/%3E%3C/svg%3E"

const FRONT_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GenosSIG</title>
<link rel="icon" href="${FAVICON}">
<style>
:root {
  --bg-primary: #0d0f12;
  --bg-secondary: #14171c;
  --bg-tertiary: #1c2026;
  --text-primary: #e8eaed;
  --text-secondary: #9aa3ad;
  --text-tertiary: #5c6570;
  --accent: #4c8dff;
  --ok: #34c77b;
  --border-subtle: #262b33;
  --radius-md: 10px;
  --space-2: 8px;
  --space-3: 12px;
  --space-5: 24px;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100dvh;
  display: grid;
  place-items: center;
  padding: var(--space-5);
  font: 15px/1.6 var(--font);
  background: var(--bg-primary);
  color: var(--text-primary);
}
main { width: min(560px, 100%); text-align: center; }
h1 { margin: 0; font-size: 28px; letter-spacing: -0.02em; }
.tag { margin: var(--space-2) 0 var(--space-5); color: var(--accent); font-weight: 600; }
p { margin: 0 0 var(--space-5); color: var(--text-secondary); }
.stats {
  display: flex;
  justify-content: center;
  gap: var(--space-3);
  margin-bottom: var(--space-5);
}
.stat {
  flex: 1;
  padding: var(--space-3);
  background: var(--bg-secondary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}
.stat b { display: block; font: 20px var(--mono); color: var(--ok); }
.stat span { font-size: 12px; color: var(--text-tertiary); }
.map {
  margin-bottom: var(--space-2);
  background: var(--bg-secondary);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  overflow: hidden;
}
.map svg { display: block; width: 100%; height: auto; }
.map .grid { stroke: var(--border-subtle); stroke-width: 0.3; opacity: 0.5; }
.map .land { fill: var(--bg-tertiary); }
.peer-dot { fill: var(--ok); animation: pulse 2s ease-in-out infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
@media (prefers-reduced-motion: reduce) { .peer-dot { animation: none; } }
.map-note { margin: 0 0 var(--space-5); font-size: 12px; color: var(--text-tertiary); }
footer { font-size: 13px; color: var(--text-tertiary); }
footer a { color: var(--text-secondary); }
</style>
</head>
<body>
<main>
<h1>GenosSIG</h1>
<div class="tag">GenosDB Signalling Relay</div>
<p>Ephemeral WebRTC signalling for <strong>GenosDB</strong> applications.
Peers meet here and then talk directly — nothing is stored, and only
GenosRTC traffic is accepted. This is not a general-purpose Nostr relay.</p>
<div class="stats">
<div class="stat"><b id="connections">–</b><span>connections</span></div>
<div class="stat"><b id="rooms">–</b><span>active rooms</span></div>
</div>
<div class="map">
<svg viewBox="0 0 360 180" role="img" aria-label="World map of connected peers">
<path class="grid" d="M30 0V180M60 0V180M90 0V180M120 0V180M150 0V180M180 0V180M210 0V180M240 0V180M270 0V180M300 0V180M330 0V180M0 30H360M0 60H360M0 90H360M0 120H360M0 150H360"/>
<g class="land">
<path d="M14 28 L15 22 40 20 60 17 85 10 105 8 120 20 125 38 115 45 105 50 100 58 98 65 90 70 83 74 85 78 95 80 102 83 98 81 95 78 85 73 75 68 69 65 66 60 59 55 56 49 56 42 49 35 44 32 28 30 Z"/>
<path d="M102 83 L110 79 119 80 128 86 136 93 143 98 145 100 141 107 138 113 132 118 127 124 122 129 115 135 112 142 108 144 105 138 107 130 109 120 110 108 104 103 99 96 101 90 Z"/>
<path d="M128 25 L133 12 145 7 157 10 160 18 150 26 138 30 Z"/>
<path d="M174 55 L190 53 200 57 212 59 223 79 231 79 226 91 220 95 219 106 215 115 206 124 198 124 194 113 192 103 188 91 189 86 184 84 172 85 167 81 163 75 164 69 170 60 Z"/>
<path d="M171 53 L171 47 178 42 183 39 188 35 190 32 198 27 205 19 220 22 235 19 255 17 275 13 295 14 315 18 330 20 350 23 358 25 356 28 343 30 337 37 322 38 315 45 309 49 302 53 299 60 292 68 287 75 284 81 281 87 279 82 275 76 271 70 265 70 260 77 256 82 252 71 247 66 239 65 232 65 229 61 226 75 224 78 216 61 212 59 207 53 199 50 192 46 185 47 179 53 Z"/>
<path d="M293 112 L302 107 311 101 317 102 322 101 327 109 333 117 330 127 320 128 312 122 304 123 295 125 Z"/>
</g>
<g id="dots"></g>
</svg>
</div>
<p class="map-note">Live connections — approximate, city-level, aggregated</p>
<footer><a href="https://genosdb.com">genosdb.com</a></footer>
</main>
<script>
const SVG_NS = 'http://www.w3.org/2000/svg'
const refresh = () =>
  fetch('/health').then(r => r.json()).then(h => {
    document.getElementById('connections').textContent = h.connections
    document.getElementById('rooms').textContent = h.rooms
    document.getElementById('dots').replaceChildren(...(h.locations || []).map(l => {
      const dot = document.createElementNS(SVG_NS, 'circle')
      dot.setAttribute('cx', (l.lon + 180).toFixed(1))
      dot.setAttribute('cy', (90 - l.lat).toFixed(1))
      dot.setAttribute('r', String(Math.min(2 + Math.sqrt(l.n), 6)))
      dot.setAttribute('class', 'peer-dot')
      const label = document.createElementNS(SVG_NS, 'title')
      label.textContent = (l.cc || '?') + ' ×' + l.n
      dot.append(label)
      return dot
    }))
  }).catch(() => {})
refresh()
setInterval(refresh, 5000)
</script>
</body>
</html>`

const relayStub = (env: Env) =>
  env.RELAY_WEBSOCKET.get(env.RELAY_WEBSOCKET.idFromName(DO_NAME), { locationHint: DO_HINT })

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      // City-level geo from the edge (free, no external lookup), rounded to
      // ~11 km for privacy. Authoritative: a client-supplied ?geo is replaced.
      const cf = request.cf as { latitude?: string; longitude?: string; country?: string } | undefined
      const upgradeUrl = new URL(request.url)
      const lat = Number(cf?.latitude)
      const lon = Number(cf?.longitude)
      if (Number.isFinite(lat) && Number.isFinite(lon)) {
        upgradeUrl.searchParams.set('geo', `${lat.toFixed(1)},${lon.toFixed(1)},${cf?.country ?? ''}`)
      } else {
        upgradeUrl.searchParams.delete('geo')
      }
      return relayStub(env).fetch(new Request(upgradeUrl, request))
    }
    if (url.pathname === '/') {
      return new Response(FRONT_PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })
    }
    if (url.pathname === '/health') {
      return relayStub(env).fetch(request)
    }
    if (url.pathname === '/favicon.ico') {
      return new Response(null, { status: 204 })
    }
    return new Response('Not found', { status: 404 })
  },
}
