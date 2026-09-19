# rust-acestream-proxy
A tiny Rust service that pulls an AceStream engine stream **once** and re-serves it to many listeners — as audio-only (for cars and phones) or as fragmented MP4 with the video track copied untouched (for browsers). The full muxed stream (~3–6 Mbps) becomes an audio stream of ~100–300 kbps, so the mobile-data leg shrinks by an order of magnitude. Every mode of [docker-acestream-webplayer](https://github.com/trexx/docker-acestream-webplayer) — Stream, Listen and Cast — fetches from it; no client talks to the engine directly.

## Endpoints

```
GET /audio?id=<40-hex content id>[&fmt=adts|mp3]
GET /video?id=<40-hex content id>
GET /status
GET /healthz
```

* `id` — the AceStream content id (40 hex chars, required).
* `fmt` — audio output format. `adts` (AAC, default — browsers and Chromecast Audio both play it, and it keeps the stream-copy path) or `mp3` (fallback for devices that won't play ADTS).

`/video` serves fragmented MP4 that a browser `<video>` element plays natively as a progressive stream; MSE and players such as mpv take it too. The engine to pull from comes from the required `ENGINE_HOST` env var. `HEAD` on either stream endpoint is answered without starting anything, since players commonly probe with one before the GET.

## One engine pull per content id

Every listener used to cost a separate full-bitrate pull from the engine. Now a single puller holds one engine session per content id and fans the raw MPEG-TS out to one ffmpeg per output format, each of which fans out to its own listeners:

```
engine ──1 pull──> puller ──raw TS──┬──> ffmpeg (adts) ──> listeners
                                    └──> ffmpeg (fmp4) ──> listeners
```

So a second listener costs the engine nothing, whether or not they want the same format. Teardown is refcounted from the bottom up: the last listener leaving a format stops its ffmpeg, and the last format stopping closes the engine session (with an explicit `method=stop`, rather than waiting for the connection to lapse).

Not on the spot, though. A reconnect is the common case for a live viewer — a phone changing networks, a player restarting, a listener evicted for falling behind — and a cold start costs the engine's swarm discovery, typically 10–25 s. So an encoder **lingers** for `ENCODER_LINGER_S` (default 15) after its last listener leaves, and an engine pull for `ENGINE_LINGER_S` (default 60) after its last encoder stops. A viewer who comes back inside that window joins the running ffmpeg — measured, the init segment arrived in 30 ms — and one who comes back a little later still skips swarm discovery. `/status` shows what is lingering.

The source is identified **once** per content id, from the PMT in the first packets of the pull — no ffprobe, no preroll to wait for — so the first listener starts as soon as the engine sends anything and later ones with no delay at all. MPEG audio's layer, which the PMT does not carry and which decides whether `fmt=mp3` copies or transcodes, is read from the first frame header. ffprobe remains only as a fallback, over a 256 KB preroll, for a private stream the parser cannot name.

## Copy-first design

| Endpoint | Source audio | Video | Audio |
| --- | --- | --- | --- |
| `/audio&fmt=adts` | AAC | — | **copied** |
| `/audio&fmt=adts` | anything else | — | transcoded to AAC 128k |
| `/audio&fmt=mp3` | MP3 | — | **copied** |
| `/audio&fmt=mp3` | anything else | — | transcoded to MP3 128k |
| `/video` | AAC | **copied** | **copied** |
| `/video` | anything else | **copied** | transcoded to AAC 128k |

Video is always stream-copied — that is where the CPU saving is, and no pixel is ever decoded. Audio is copied when the source codec is already browser-playable. The asymmetry on `/video` is not optional: AC-3, E-AC-3 and MP2 are legal inside MP4 but browsers will not decode them, so a blanket `-c copy` would produce video with silence.

## Latency

Tuned for low latency throughout: `-flush_packets 1` and `-avioflags direct` on ffmpeg's *output* stop it buffering ~32KB before it writes (at 128 kbps that alone is ~2 s), the fan-out hands every chunk straight to each listener's socket, and `TCP_NODELAY` is set so Nagle can't sit on a frame.

The figures below were measured on ffmpeg 8.1 with a constant-bitrate 3.5 Mbps 720p test stream (3 s GOP) fed through a pipe at real-time rate, the way the puller feeds ffmpeg; the recipe is under *Local development*.

### Starting an encoder

ffmpeg must see a keyframe before it can copy H.264 into MP4 (the SPS/PPS it needs arrive only with one), and MPEG-TS has no header, so it analyses `-analyzeduration` worth of input from wherever it starts reading — no less, and it cannot stop early. Three things follow, and the service is built around them.

**A new encoder is primed from the replay window** — the trailing ~12 s of raw TS kept per engine pull — instead of attaching to live data mid-GOP, which on a real 720p stream took 14 s in one trial and simply never succeeded in another. A video encoder is primed from the **newest keyframe** in the window, so ffmpeg's first bytes are a keyframe and its analysis is satisfied at pipe speed. The window is scanned for keyframes as it fills: PAT → PMT → video PID → SPS/IDR NAL (HEVC and MPEG-2 likewise), with the transport stream's random-access flag only as a fallback, since some muxers set it on every packet. An audio encoder is primed with the last 1.5 s and needs no keyframe.

**Every replayed byte is lag.** ffmpeg in copy mode cannot skip ahead, so whatever an encoder is primed with, its listeners watch late for as long as it runs. Priming from the newest keyframe bounds that at one GOP. Replaying a fixed 4 MB, as this service used to, cost 10–13 s at typical bitrates — permanently, for every listener.

**`-avioflags direct` must not be set on ffmpeg's input.** The mpegts demuxer scans the start of its input for the PAT/PMT and then seeks back through the AVIO buffer to re-read it; with direct I/O there is no buffer, the seek fails (`Unable to seek back to the start`, logged only at info level) and everything the scan consumed is discarded — measured at 1.5–2.6 MB per encoder start, most of a replay window and several seconds of a live stream, varying from run to run. This was the dominant startup cost, and the reason the replay window could never be shrunk. The buffer costs no latency: a pipe read returns whatever is there.

Time from encoder start to first output, input fed at real-time rate:

| | before | now |
| --- | --- | --- |
| audio, empty window | 8.1 s | 3.7 s |
| video, empty window | 10.2 s | 3.2 s |
| audio, warm pull | ~1.5 s | ~1 s |
| video, warm pull, primed from a keyframe | 0.6 s | ~0.5 s, plus up to one fragment |

"Empty window" means the request arrived before the pull had anything but its 256 KB preroll, which only the very first listener after a cold start can see, and an AceStream engine bursts tens of megabytes at start so even that usually finds a keyframe. Attaching to an encoder already running takes under a millisecond.

`-fflags nobuffer` looks like a low-latency setting but measured *worse* — about 2 s on video, 0.6 s on audio — because it slows stream analysis; it is deliberately not used.

### Fragments

`/video` has a floor that no amount of flushing moves: an fMP4 `moof` carries its fragment's sample table, so it cannot be written until the fragment is complete. With keyframe-only fragmentation every fragment is one GOP and is emitted when the *next* keyframe arrives — measured, a 3 s GOP gave a `moof` every 3.0 s, each about 3.1 s after its own start — so a viewer sits a whole GOP behind, and a joiner waits up to another.

So fragments are also cut on a timer, `FRAG_DURATION_MS` (default 1000). ffmpeg combines the two conditions: every keyframe still opens a fragment, and the fragments in between are a second long. The scanner reads each `moof`'s sample flags and aligns a late joiner to the next fragment that **starts on a keyframe**, so the timed cuts cost no artifacts — a bare `-frag_duration`, which this knob used to set, opened every fragment but the first on a non-sync sample, and a late joiner decoded garbage until the next IDR. A joiner still waits up to one GOP for a keyframe fragment, but then sits ~1 s behind the encoder instead of ~3 s. `FRAG_DURATION_MS=0` restores keyframe-only fragmentation.

### Reconnects and late joiners

Late joiners on `/video` are handled: the init segment (`ftyp` + `moov`) is cached and replayed to every new listener, which is then aligned to the next keyframe fragment. Audio formats need none of this — ADTS and MP3 resynchronise on any byte offset. With the encoder and engine lingers described above, a rejoin during a match costs no engine round trip at all: measured end to end against a stand-in engine, a `/video` client that reconnected 2 s after leaving had its init segment in 30 ms and media at the next keyframe fragment, and `HEAD` probes cost nothing.

A listener that falls more than 8 s behind the encoder is disconnected rather than allowed to stall the shared stream or catch up through stale data; thanks to the linger its reconnect lands at the live edge in well under a second. A client that vanishes without closing is cut off by the same rule once its socket stops draining, and by a 30 s write timeout in any case, so a lost phone no longer keeps an engine session alive for the quarter-hour TCP takes to give up on its own.

Cold start adds P2P swarm discovery, typically 10–25 s before the engine serves anything at all. Steady-state glass-to-glass latency has not been measured against a real engine.

Throughput is not the constraint the copy-first design was built to avoid. Serving a 1080 p 6.1 Mbps stream to five listeners across three formats simultaneously, the three ffmpeg processes used **0.5–4.1 % CPU** — the stream-copy paths are nearly free, and only the MP3 transcode registers at all.

## Configuration

| Env var | Default | Purpose |
| --- | --- | --- |
| `ENGINE_HOST` | *(required)* | AceStream engine `host[:port]` to pull streams from |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `FRAG_DURATION_MS` | `1000` | fMP4 fragment duration; keyframes always open a fragment as well. `0` fragments on keyframes only, which costs a full GOP of latency |
| `ENCODER_LINGER_S` | `15` | How long an ffmpeg outlives its last listener, so a reconnect joins it. `0` disables |
| `ENGINE_LINGER_S` | `60` | How long an engine pull outlives its last encoder, so a reconnect skips swarm discovery. `0` disables |

## Monitoring

`GET /status` returns JSON describing every active pull, the encoders hanging off it, their listeners, and the engine's own view of each swarm (peers, speeds — passed through verbatim from the engine's `stat_url`, since its shape varies by version):

```json
{
  "uptime_s": 3841,
  "summary": { "engine_pulls": 1, "encoders": 2, "listeners": 3 },
  "streams": [{
    "content_id": "…",
    "uptime_s": 402,
    "bytes_from_engine": 301989888,
    "source": { "video": "h264", "audio": "ac3" },
    "engine": { "status": "dl", "peers": 12, "speed_down": 786, "speed_up": 120 },
    "lingering": false,
    "outputs": [
      { "format": "adts", "video": "drop", "audio": "transcode", "lingering": false,
        "listeners": [{ "peer": "10.0.0.5:51234", "uptime_s": 400, "bytes_sent": 6400000 }] },
      { "format": "fmp4", "video": "copy", "audio": "transcode", "lingering": true,
        "listeners": [] }
    ]
  }]
}
```

`summary.engine_pulls` staying at one while `encoders` and `listeners` climb is the fan-out doing its job. `lingering` marks an encoder with no listener, or a pull with no encoder, being kept for a reconnect. `/healthz` is there for probes.

## Deployment

Run it in the same cluster as the engine — it pulls the full muxed stream per content id. Set `ENGINE_HOST` to the engine's in-cluster address.

## Casting to a Chromecast

A video Chromecast is sent `/video` and plays it directly; that has been verified on a real device. Audio-only cast targets can't decode the muxed TS — hand them this service's stream instead. Chromecast Audio plays AAC, so the default (ADTS) output works and keeps the stream-copy path: the device receives the original audio untouched. The webplayer expects this service path-routed at `/audio` on the engine host, so the Home Assistant automation should call `media_player.play_media` with `http://<host from the cast payload>/audio?id=<id>` and `media_content_type: "music"` for audio devices. If a device won't play ADTS, append `&fmt=mp3` as a fallback.

The webplayer's Cast picks the endpoint per device: entries marked audio-only are sent `/audio`, the rest `/video`.

## Local development

```sh
cargo test
ENGINE_HOST=my-engine:6878 cargo run

podman build -t rust-acestream-proxy .
podman run --rm -p 8080:8080 -e ENGINE_HOST=my-engine:6878 rust-acestream-proxy
curl -v 'http://127.0.0.1:8080/audio?id=<content id>' | mpv -
curl -v 'http://127.0.0.1:8080/video?id=<content id>' | mpv -
```

No AceStream engine is needed to exercise the service: point `ENGINE_HOST` at any HTTP server that returns MPEG-TS on every path. `ffmpeg -f lavfi -i testsrc2 -f lavfi -i sine -c:v libx264 -c:a ac3 -f mpegts test.ts` generates a suitable source.

For timing measurements, make the source constant-bitrate so that bytes map to seconds, then serve it at that rate: `-c:v libx264 -g 75 -keyint_min 75 -sc_threshold 0 -b:v 2800k -minrate 2800k -maxrate 2800k -bufsize 2800k -x264-params nal-hrd=cbr -c:a aac -muxrate 3500000` gives a 3 s GOP at exactly 437,500 bytes/s, and starting the feed a fraction of a GOP in (`tail -c +568751`) reproduces a mid-GOP attach. The ffmpeg arguments the service uses are the `plan` function's output in `src/format.rs`.
