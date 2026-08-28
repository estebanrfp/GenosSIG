# GenosSIG

GenosDB signalling relay — ephemeral WebRTC signalling (SDP/ICE) for GenosDB
peer discovery, on Cloudflare Workers with one Durable Object.

Only GenosDB (GenosRTC) traffic is accepted: Nostr-shaped ephemeral events
(kinds 20000-29999) whose kind is derived from the room topic, carrying exactly
one `["x", topic]` tag. Nothing is stored — no database, no history, no replay.
Peers meet here and then talk directly to each other.

This relay is not a general-purpose Nostr relay: generic filters are refused
with `CLOSED` and non-GenosRTC events with `OK false`.

## Runs on Cloudflare's free plan

GenosSIG is built to fit the Cloudflare Workers free plan. It needs a Worker and
one Durable Object, and nothing else: no D1, no KV, no R2, no cron triggers, no
paid add-ons to enable. Because signalling is ephemeral, nothing is persisted
between sessions — there is no database to provision, migrate or clean up.

Deploy it on a free Cloudflare account and it works. Run your own and the peers
of your app never depend on anyone else's relay.

## Deploy

    npm install
    npm run build        # src/index.ts -> worker.js
    npx wrangler deploy

Wrangler will ask you to log in the first time. When it finishes it prints your
endpoint:

    wss://genosdb-relay.<your-subdomain>.workers.dev

Two notes worth keeping: `worker.js` is the prebuilt bundle, so editing
`src/` without `npm run build` deploys nothing; and the free plan rejects a
`[limits]` block outright, at any value, so leave it out.

Visit the same host over https for a status page, and `/health` for the same
numbers as JSON.

## Use it from GenosDB

Pass your endpoint to GenosRTC and your peers will meet through it:

    const db = await gdb('my-app', {
      rtc: { relayUrls: ['wss://genosdb-relay.<your-subdomain>.workers.dev'] }
    })

Listing more than one relay is a good idea: discovery rides whichever answers
first, so a second entry keeps the app working if one is unreachable.

## Protocol (the GenosRTC subset)

- `["REQ", subId, {kinds: [k], since, "#x": [topic]}]` → `EOSE` (immediate — there is no history)
- `["EVENT", {...}]` → schnorr-verified (id recomputed), kind↔topic coherence enforced → `OK`, then fan-out to matching subscribers
- `["CLOSE", subId]` → drops the subscription
- `GET /` → status page · `GET /health` → JSON stats

Clients that do not speak this subset are refused, and evicted after repeated
violations.

## Benchmark

`tools/relay-benchmark.html` measures connect, EOSE and delivery against any
list of relays, so you can compare your deployment with public ones. Serve it
over http(s) — `file://` has no `crypto.subtle`.

## License

MIT — see [LICENSE](LICENSE).

## Author

Esteban Fuster Pozzi (@estebanrfp) - Full Stack JavaScript Developer
