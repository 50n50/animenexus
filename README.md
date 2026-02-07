# Anime Nexus Script

**A working Anime Nexus stream player powered by an episode identifier and sheer optimism (performance not included).**

*Honestly man, who even comes up with a protection like this?*

## Q&A

**Why?**
Boredom.

**How is this useful?**
It isn't.

## Usage

```bash
python anime_nexus_grab.py <episode_id>
```

**Example:**
```bash
python anime_nexus_grab.py 019b9e8f-edf6-71a7-87c5-c45f64297245
```

Episodes will stream in a browser-based HLS.js player with automatic segment prefetching.

## Technical Workflow

### 1. Device Fingerprinting
- **Method**: SHA-256 hash of JSON object containing:
  - User-Agent (Chrome 131 impersonation)
  - Language, platform, screen dimensions, pixel ratio, color depth
  - Touch points, timezone, random UUID
- **Purpose**: Unique device identifier submitted to WebSocket for anti-bot validation
- **Location**: `X-Client-Fingerprint`, `X-Fingerprint` headers

### 2. Session Bootstrap
- **Endpoint**: `https://api.anime.nexus/sanctum/csrf-cookie` (GET)
- **Library**: `curl_cffi` with Chrome 131 impersonation
- **Output**: Laravel session cookie set to HTTP client for subsequent requests

### 3. Stream Metadata Fetch
- **Endpoint**: `https://api.anime.nexus/api/anime/details/episode/stream?id={episode_id}`
- **Headers**: Fingerprint + standard CORS headers
- **Response**: JSON containing:
  - HLS master manifest URL
  - Video metadata (duration, available qualities, audio languages)
  - Subtitle tracks array

### 4. WebSocket Token System
- **Connection**: Socket.IO to `wss://prd-socket.anime.nexus/api/socket` namespace `/video`
- **Authentication Flow**:
  1. Connect with query params: `videoId`, `fingerprint`, `m3u8Url`
  2. Server sends `connected` event with `sessionId`
  3. Emit `getToken` request with `requestType: "manifest"`
  4. Handle challenge-response if `reauth-required` event fires:
     - Decrypt secret using AES-GCM (key: `CLIENT_ENCRYPT_KEY`)
     - Compute HMAC-SHA256 of `challenge:fingerprint` with decrypted secret
     - Respond with challenge + HMAC response
- **Token Pool Management**:
  - Queue-based token cache with max capacity: 40 tokens
  - 10 background threads continuously request fresh tokens
  - Maintains minimum threshold: 35 tokens ready
  - Requests new token when queue size drops below threshold
  - Timeout per token request: 2 seconds
  - Prevents rate-limiting by pre-fetching tokens before playback

### 5. Manifest Fetching & Playlist Parsing
- **Master Manifest**:
  - Authenticated URL: `{hls_url}?token={token}&requestType=manifest&sessionId={sessionId}`
  - Parse `#EXT-X-STREAM-INF` entries for available bitrates
  - Select highest bandwidth variant (trim master manifest)
- **Variant Playlists**:
  - Each variant URL contains segment list (M3U8 format)
  - Parse `#EXTINF` entries for segment metadata
  - Extract absolute segment URLs (rewrite relative paths to absolute)
  - Build in-memory segment index per playlist

### 6. Local Reverse Proxy
- **HTTP Server**:
  - ThreadedHTTPServer binding to `127.0.0.1:{random_port}`
  - URL rewriting: manifest/segment URLs → `http://127.0.0.1:{port}/proxy?url={encoded_url}`
- **Segment Caching**:
  - In-memory dictionary cache: `{url: (content_bytes, content_type)}`
  - Thread-safe access via lock
- **Prefetching Strategy**:
  - **Initial**: Prefetch all init segments (codec initialization) + all segments from master playlist concurrently
  - **Continuous Background Loop**:
    - Check every 500ms for missing segments across all playlists
    - Download any cached/non-downloading segments in 24 parallel workers
    - Up to 3 retries per segment on failure
    - Request fresh token per segment via WebSocket
    - Segment timeout: 15 seconds per request
- **Manifest Rewriting**:
  - Replace all segment URLs with proxy URLs
  - Preserve M3U8 structure and metadata tags
  - Apply to master + variant playlists dynamically

### 7. HLS.js Video Player
- **Configuration**:
  - Buffer: 120-600s max, adaptive backpressure
  - Max buffer size: 100MB
  - Fragment retry: 8 retries with exponential backoff (1-2s delay)
  - Manifest retry: 3 timeout retries, 8 error retries
  - Progressive download enabled (stream while buffering)
- **HTML Player**:
  - Embedded HLS.js v1.5.17 from CDN
  - Auto-play with video controls
  - Status overlay showing buffer depth (updates per segment loaded)
  - Auto-hide UI after 3s of playback
  - Error recovery: auto-restart on fatal errors
- **Keepalive**:
  - /ping endpoint every 3s to prevent proxy timeout
  - beforeunload event triggers /close endpoint on browser exit

### 8. Cleanup & Monitoring
- **Output Format**: 
  - `[*]` prefix for informational messages
  - `[!]` prefix for errors
  - Progress indicator: segment count updates every 20 segments
- **Shutdown**:
  - Detect browser close via timeout (15s inactivity) or explicit close signal
  - Graceful HTTPServer shutdown
  - Socket.IO disconnect