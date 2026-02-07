import hashlib
import hmac
import json
import uuid
import sys
import time
import threading
import webbrowser
import re
import queue
import concurrent.futures
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlencode, urlparse, quote, unquote
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore

try:
    from curl_cffi import requests as cr # type: ignore
except ImportError:
    print("ERROR: curl_cffi not installed. Run: pip install curl_cffi")
    sys.exit(1)

try:
    import socketio # type: ignore
except ImportError:
    print("ERROR: python-socketio not installed. Run: pip install python-socketio[client] websocket-client")
    sys.exit(1)

CLIENT_ENCRYPT_KEY = "0fe5ccc60dd395c1a9b9ba6e1238e0857575aa77df7c9294acdfdacfeeb5de67"

SOCKET_URL = "https://prd-socket.anime.nexus"
SOCKET_PATH = "/api/socket"
SOCKET_NAMESPACE = "/video"

def decrypt_secret(encrypted_string: str) -> str:
    parts = encrypted_string.split(":")
    iv_hex, tag_hex, ciphertext_hex = parts[0], parts[1], parts[2]
    
    key_hex = CLIENT_ENCRYPT_KEY
    if len(key_hex) < 64:
        key_hex = key_hex.ljust(64, "0")
    elif len(key_hex) > 64:
        key_hex = key_hex[:64]
    
    key_bytes = bytes.fromhex(key_hex)
    iv_bytes = bytes.fromhex(iv_hex)
    tag_bytes = bytes.fromhex(tag_hex)
    ct_bytes = bytes.fromhex(ciphertext_hex)
    
    # WebCrypto AES-GCM: combined = ciphertext || tag
    combined = ct_bytes + tag_bytes
    
    aesgcm = AESGCM(key_bytes)
    plaintext = aesgcm.decrypt(iv_bytes, combined, None)
    return plaintext.decode("utf-8")


def solve_challenge(challenge: str, decrypted_secret: str, fingerprint: str) -> str:
    message = f"{challenge}:{fingerprint}"
    key = decrypted_secret.encode("utf-8")
    msg = message.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def generate_fingerprint() -> str:
    data = {
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/131.0.0.0 Safari/537.36",
        "language": "en-US",
        "platform": "Win32",
        "screenWidth": 1920,
        "screenHeight": 1080,
        "pixelRatio": 1,
        "colorDepth": 24,
        "touchPoints": 0,
        "timezone": "Europe/Amsterdam",
        "random": str(uuid.uuid4()),
    }
    raw = json.dumps(data, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_session(fingerprint: str) -> cr.Session:
    s = cr.Session(impersonate="chrome131")

    resp = s.get("https://api.anime.nexus/sanctum/csrf-cookie",
                  headers={
                      "Accept": "application/json, text/plain, */*",
                      "Origin": "https://anime.nexus",
                      "Referer": "https://anime.nexus/",
                  },
                  timeout=15)

    return s

def get_api_headers(fingerprint: str) -> dict:
    return {
        "Accept": "application/json, text/plain, */*",
        "X-Client-Fingerprint": fingerprint,
        "x-fingerprint": fingerprint,
        "Origin": "https://anime.nexus",
        "Referer": "https://anime.nexus/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }


def fetch_stream(session: cr.Session, headers: dict, episode_id: str) -> dict | None:
    url = "https://api.anime.nexus/api/anime/details/episode/stream"
    params = {"id": episode_id}

    resp = session.get(url, params=params, headers=headers, timeout=3)

    if resp.status_code == 200:
        return resp.json()
    else:
        return None

class TokenSystem:

    def __init__(self, video_id: str, fingerprint: str, m3u8_url: str,
                 session_cookie: str = ""):
        self.video_id = video_id
        self.fingerprint = fingerprint
        self.m3u8_url = m3u8_url
        self.session_cookie = session_cookie

        self.session_id = None
        self.token = None
        self.connected_event = threading.Event()
        self.token_event = threading.Event()
        self.error = None
        self.challenge_ref = None

        self.auth_data = None

        self.sio = socketio.Client(
            logger=False,
            engineio_logger=False,
        )
        self._setup_handlers()

    def _setup_handlers(self):

        @self.sio.on("connect", namespace=SOCKET_NAMESPACE)
        def on_connect():
            pass

        @self.sio.on("connected", namespace=SOCKET_NAMESPACE)
        def on_connected(data):
            if isinstance(data, dict) and data.get("sessionId"):
                self.session_id = data["sessionId"]
            self.connected_event.set()
            self._request_token()

        @self.sio.on("token", namespace=SOCKET_NAMESPACE)
        def on_token(data):
            if isinstance(data, dict) and data.get("token"):
                self.token = data["token"]
                self.token_event.set()

        @self.sio.on("reset-challenge", namespace=SOCKET_NAMESPACE)
        def on_reset_challenge(data):
            self.challenge_ref = data

        @self.sio.on("reauth-required", namespace=SOCKET_NAMESPACE)
        def on_reauth_required(data):
            if isinstance(data, dict) and data.get("challenge") and data.get("encryptedSecret"):
                try:
                    decrypted = decrypt_secret(data["encryptedSecret"])
                    response = solve_challenge(data["challenge"], decrypted, self.fingerprint)

                    self.auth_data = {
                        "type": "challenge",
                        "challenge": data["challenge"],
                        "encryptedSecret": data["encryptedSecret"]
                    }

                    self.sio.emit("reauth-response", {
                        "challenge": data["challenge"],
                        "response": response
                    }, namespace=SOCKET_NAMESPACE)
                except Exception as e:
                    self.error = str(e)

        @self.sio.on("session-renewal-ready", namespace=SOCKET_NAMESPACE)
        def on_session_renewal(data):
            if isinstance(data, dict) and data.get("challenge") and data.get("encryptedSecret"):
                try:
                    decrypted = decrypt_secret(data["encryptedSecret"])
                    response = solve_challenge(data["challenge"], decrypted, self.fingerprint)
                    self.sio.emit("session-renewal-response", {
                        "challenge": data["challenge"],
                        "response": response,
                        "oldSessionId": data.get("oldSessionId", "")
                    }, namespace=SOCKET_NAMESPACE)
                except Exception as e:
                    pass

        @self.sio.on("session-renewed", namespace=SOCKET_NAMESPACE)
        def on_session_renewed(data):
            if isinstance(data, dict) and data.get("sessionId"):
                self.session_id = data["sessionId"]
                self._request_token()

        @self.sio.on("error", namespace=SOCKET_NAMESPACE)
        def on_error(data):
            msg = data.get("message", str(data)) if isinstance(data, dict) else str(data)
            self.error = msg

        @self.sio.on("authentication-error", namespace=SOCKET_NAMESPACE)
        def on_auth_error(data):
            msg = data.get("message", str(data)) if isinstance(data, dict) else str(data)
            self.error = msg

        @self.sio.on("disconnect", namespace=SOCKET_NAMESPACE)
        def on_disconnect():
            pass

    def _request_token(self):
        def callback(response):
            if isinstance(response, dict):
                if response.get("error"):
                    self.error = response["error"]
                elif response.get("token"):
                    self.token = response["token"]
                    self.token_event.set()

        self.sio.emit("getToken", {
            "requestType": "manifest",
        }, namespace=SOCKET_NAMESPACE, callback=callback)

    def refresh_token(self) -> bool:
        self.token_event.clear()
        self._request_token()
        return self.token_event.wait(timeout=10)

    def get_fresh_token(self) -> str | None:
        if not self.sio.connected:
            return None
        result = {"token": None}
        done = threading.Event()

        def callback(response):
            if isinstance(response, dict) and response.get("token"):
                result["token"] = response["token"]
            done.set()

        try:
            self.sio.emit("getToken", {
                "requestType": "manifest",
            }, namespace=SOCKET_NAMESPACE, callback=callback)
        except Exception:
            return None

        done.wait(timeout=2)
        return result["token"]

    def start_token_pool(self, manifest_workers: int = 10):
        self._manifest_pool = queue.Queue(maxsize=40)
        self._pool_running = True

        def manifest_filler():
            while self._pool_running:
                if self._manifest_pool.qsize() < 35:
                    t = self.get_fresh_token()
                    if t:
                        self._manifest_pool.put(t)
                else:
                    time.sleep(0.01)

        for _ in range(manifest_workers):
            threading.Thread(target=manifest_filler, daemon=True).start()

        deadline = time.time() + 2
        while time.time() < deadline:
            if self._manifest_pool.qsize() >= 10:
                break
            time.sleep(0.03)

    def pool_token(self) -> str:
        try:
            return self._manifest_pool.get(timeout=5)
        except queue.Empty:
            return self.get_fresh_token() or self.token

    def pool_stats(self) -> int:
        return self._manifest_pool.qsize()

    def stop_token_pool(self):
        self._pool_running = False

    def request_segment_token(self, segment_url: str) -> str | None:
        if not self.sio.connected:
            return None
        result = {"token": None}
        done = threading.Event()

        def callback(response):
            if isinstance(response, dict) and response.get("token"):
                result["token"] = response["token"]
            done.set()

        try:
            self.sio.emit("getToken", {
                "requestType": "segment",
                "segmentUrl": segment_url,
                "videoId": self.video_id,
            }, namespace=SOCKET_NAMESPACE, callback=callback)
        except Exception:
            return None

        done.wait(timeout=2)
        return result["token"]

    def prefetch_segment_tokens(self, urls: list[str], token_cache: dict):
        if not self.sio.connected:
            return
        for url in urls:
            if url in token_cache:
                continue
            def make_cb(u):
                def callback(response):
                    if isinstance(response, dict) and response.get("token"):
                        token_cache[u] = response["token"]
                return callback
            try:
                self.sio.emit("getToken", {
                    "requestType": "segment",
                    "segmentUrl": url,
                    "videoId": self.video_id,
                }, namespace=SOCKET_NAMESPACE, callback=make_cb(url))
            except Exception:
                pass

    def connect(self):
        query = {
            "videoId": self.video_id,
            "fingerprint": self.fingerprint,
            "m3u8Url": self.m3u8_url,
        }

        headers = {
            "Origin": "https://anime.nexus",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36",
        }
        if self.session_cookie:
            headers["Cookie"] = f"anime_nexus_session={self.session_cookie}"

        try:
            query_string = urlencode(query)
            url = f"{SOCKET_URL}?{query_string}"

            self.sio.connect(
                url,
                namespaces=[SOCKET_NAMESPACE],
                socketio_path=SOCKET_PATH,
                headers=headers,
                transports=["websocket"],
                wait_timeout=15,
            )
        except Exception as e:
            self.error = str(e)
            return False

        if not self.connected_event.wait(timeout=15):
            return False

        if not self.token_event.wait(timeout=15):
            self._request_token()
            if not self.token_event.wait(timeout=10):
                return False

        return True

    def disconnect(self):
        try:
            self.sio.disconnect()
        except Exception:
            pass


def fetch_m3u8(session: cr.Session, token_system: TokenSystem,
               m3u8_url: str) -> str | None:
    separator = "&" if "?" in m3u8_url else "?"
    params = urlencode({
        "token": token_system.token,
        "requestType": "manifest",
        "sessionId": token_system.session_id,
    })
    auth_url = f"{m3u8_url}{separator}{params}"

    headers = {
        "Accept": "*/*",
        "Origin": "https://anime.nexus",
        "Referer": "https://anime.nexus/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "Cache-Control": "no-store",
    }

    if token_system.auth_data:
        if token_system.auth_data["type"] == "token":
            headers["X-WS-Token"] = token_system.auth_data["token"]
        else:
            headers["X-WS-Challenge"] = token_system.auth_data["challenge"]
            headers["X-WS-Token"] = token_system.auth_data["encryptedSecret"]
    else:
        headers["X-Video-UUID"] = token_system.video_id
        headers["X-Client-Fingerprint"] = token_system.fingerprint
        headers["X-Fingerprint"] = token_system.fingerprint
        headers["X-Session-ID"] = token_system.session_id

    resp = session.get(auth_url, headers=headers, timeout=20)

    if resp.status_code == 200:
        content = resp.text
        if content.strip().startswith("#EXTM3U") or content.strip().startswith("#EXT"):
            return content
        else:
            return None
    else:
        return None


def fetch_variant_playlists(session: cr.Session, token_system: TokenSystem,
                            master_manifest: str, base_url: str) -> dict:
    variants = {}
    lines = master_manifest.strip().splitlines()

    for i, line in enumerate(lines):
        if line.startswith("#EXT-X-STREAM-INF"):
            res = "unknown"
            for part in line.split(","):
                if "RESOLUTION=" in part:
                    res = part.split("RESOLUTION=")[1].split(",")[0]
                    break

            if i + 1 < len(lines):
                variant_path = lines[i + 1].strip()
                if not variant_path.startswith("http"):
                    variant_url = base_url + "/" + variant_path
                else:
                    variant_url = variant_path

                separator = "&" if "?" in variant_url else "?"
                params = urlencode({
                    "token": token_system.token,
                    "requestType": "manifest",
                    "sessionId": token_system.session_id,
                })
                auth_variant_url = f"{variant_url}{separator}{params}"

                headers = {
                    "Accept": "*/*",
                    "X-Video-UUID": token_system.video_id,
                    "X-Client-Fingerprint": token_system.fingerprint,
                    "X-Fingerprint": token_system.fingerprint,
                    "X-Session-ID": token_system.session_id,
                    "Origin": "https://anime.nexus",
                    "Referer": "https://anime.nexus/",
                }
                
                if token_system.auth_data:
                    if token_system.auth_data["type"] == "token":
                        headers["X-WS-Token"] = token_system.auth_data["token"]
                    else:  
                        headers["X-WS-Challenge"] = token_system.auth_data["challenge"]
                        headers["X-WS-Token"] = token_system.auth_data["encryptedSecret"]

                vresp = session.get(auth_variant_url, headers=headers, timeout=15)
                if vresp.status_code == 200:
                    variants[res] = vresp.text
                else:
                    pass

    return variants


def _trim_master_manifest(master_manifest: str) -> str:
    lines = master_manifest.strip().splitlines()

    best_bw = -1
    best_idx = -1
    best_audio_group = None
    for i, line in enumerate(lines):
        if line.startswith("#EXT-X-STREAM-INF"):
            bw = 0
            audio_group = None
            bw_match = re.search(r'BANDWIDTH=(\d+)', line)
            if bw_match:
                bw = int(bw_match.group(1))
            audio_match = re.search(r'AUDIO="([^"]+)"', line)
            if audio_match:
                audio_group = audio_match.group(1)
            if bw > best_bw:
                best_bw = bw
                best_idx = i
                best_audio_group = audio_group

    if best_idx == -1:
        return master_manifest

    out = ["#EXTM3U"]
    for line in lines:
        if line.startswith("#EXT-X-MEDIA:") and best_audio_group:
            if f'GROUP-ID="{best_audio_group}"' in line:
                out.append(line)
    out.append(lines[best_idx])
    if best_idx + 1 < len(lines):
        out.append(lines[best_idx + 1])
    
    return "\n".join(out) + "\n"


def play_with_mpv(m3u8_url: str, token_system: TokenSystem, fingerprint: str,
                  master_manifest: str, session: cr.Session) -> None:
    print("[*] Setting up player...")
    
    cdn_headers = {
        "X-Video-UUID": token_system.video_id,
        "X-Client-Fingerprint": fingerprint,
        "X-Fingerprint": fingerprint,
        "X-Session-ID": token_system.session_id,
        "Origin": "https://anime.nexus",
        "Referer": "https://anime.nexus/",
    }
    if token_system.auth_data:
        if token_system.auth_data["type"] == "token":
            cdn_headers["X-WS-Token"] = token_system.auth_data["token"]
        else:
            cdn_headers["X-WS-Challenge"] = token_system.auth_data["challenge"]
            cdn_headers["X-WS-Token"] = token_system.auth_data["encryptedSecret"]

    ts_ref = token_system
    _thread_local = threading.local()
    
    def _get_session():
        if not hasattr(_thread_local, 'session'):
            _thread_local.session = cr.Session(impersonate="chrome131")
        return _thread_local.session
    
    def _cdn_fetch(url, token, request_type):
        params = urlencode({"token": token, "requestType": request_type, "sessionId": ts_ref.session_id})
        sep = "&" if "?" in url else "?"
        return _get_session().get(f"{url}{sep}{params}", headers=cdn_headers, timeout=15)
    
    def _fetch_with_token(url, request_type, max_retries=3):
        for _ in range(max_retries):
            tok = ts_ref.get_fresh_token() if request_type == "manifest" else ts_ref.request_segment_token(url)
            if not tok:
                continue
            try:
                r = _cdn_fetch(url, tok, request_type)
                if r.status_code == 200:
                    return (r.content, r.headers.get("Content-Type", "application/octet-stream"))
            except Exception:
                pass
        return None
    
    cache = {}
    downloading = set()
    cache_lock = threading.Lock()
    playlist_segments = {}
    seg_to_playlist = {}
    seg_to_index = {}
    
    trimmed_master = _trim_master_manifest(master_manifest)
    trimmed_urls = []
    for line in trimmed_master.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and s.startswith("http"):
            trimmed_urls.append(s)
        if 'URI="' in s:
            for m in re.finditer(r'URI="([^"]+)"', s):
                u = m.group(1)
                if u.startswith("http"):
                    trimmed_urls.append(u)
    trimmed_urls = list(dict.fromkeys(trimmed_urls))

    init_segments = []

    def _prefetch_playlist(url):
        result = _fetch_with_token(url, "manifest")
        if not result:
            return
        content, _ = result
        if not (b"#EXTM3U" in content[:20] or b"#EXTINF" in content[:5000]):
            return
        text = content.decode("utf-8", errors="replace")
        base = url.rsplit("/", 1)[0] + "/"
        seg_list = []
        for ln in text.splitlines():
            sv = ln.strip()
            if 'URI="' in sv:
                for m2 in re.finditer(r'URI="([^"]+)"', sv):
                    u2 = m2.group(1)
                    if not u2.startswith("http"):
                        u2 = base + u2
                    init_segments.append(u2)
            elif sv and not sv.startswith("#"):
                seg_url = sv if sv.startswith("http") else base + sv
                seg_list.append(seg_url)
        playlist_segments[url] = seg_list
        for idx, su in enumerate(seg_list):
            seg_to_playlist[su] = url
            seg_to_index[su] = idx
        cache[url] = (content, "application/vnd.apple.mpegurl")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(trimmed_urls) or 1) as pool:
        pool.map(_prefetch_playlist, trimmed_urls)

    init_segments = list(dict.fromkeys(init_segments))

    def _fetch_seg(url):
        if url in cache:
            return
        r = _fetch_with_token(url, "segment")
        if r:
            with cache_lock:
                cache[url] = r
    
    def _prefetch_batch(urls):
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(urls), 24)) as pool:
            pool.map(_fetch_seg, urls)
    
    threading.Thread(target=_prefetch_batch, args=(init_segments,), daemon=True).start()

    def _aggressive_prefetcher():
        total_segs = sum(len(s) for s in playlist_segments.values())
        done_count = [0]

        def _dl(url):
            try:
                r = _fetch_with_token(url, "segment", max_retries=3)
                if r:
                    with cache_lock:
                        cache[url] = r
                    done_count[0] += 1
                    if done_count[0] % 20 == 0:
                        print(f"[*] Prefetched {done_count[0]}/{total_segs} segments")
            except Exception:
                pass
            finally:
                downloading.discard(url)

        for _pl_url, segs in playlist_segments.items():
            batch = []
            for seg in segs:
                if seg not in cache and seg not in downloading:
                    batch.append(seg)
                    downloading.add(seg)
            if batch:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(batch), 24)) as p:
                    p.map(_dl, batch)
        if done_count[0]:
            print(f"[*] Prefetched {done_count[0]}/{total_segs} segments")

        while True:
            time.sleep(0.5)
            for _pl_url, segs in playlist_segments.items():
                batch = []
                for seg in segs:
                    if seg not in cache and seg not in downloading:
                        batch.append(seg)
                        downloading.add(seg)
                if batch:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(batch), 24)) as p:
                        p.map(_dl, batch)
    
    threading.Thread(target=_aggressive_prefetcher, daemon=True).start()
    
    total_segs = sum(len(s) for s in playlist_segments.values())
    print(f"[*] {len(cache)} playlists cached, prefetching {total_segs} segments...")
    
    PLAYER_HTML = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Anime Player</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { 
  width: 100%%; height: 100%%; 
  background: #0a0a0a; 
  overflow: hidden;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
#container {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%%;
  height: 100%%;
  background: #000;
}
video { 
  max-width: 100%%;
  max-height: 100%%;
  width: auto;
  height: auto;
  object-fit: contain;
}
#status {
  position: fixed;
  bottom: 20px;
  right: 20px;
  color: #4ade80;
  font: 13px 'Courier New', monospace;
  letter-spacing: 0.5px;
  background: rgba(0, 0, 0, 0.85);
  padding: 10px 14px;
  border-radius: 6px;
  border: 1px solid rgba(74, 222, 128, 0.2);
  z-index: 999;
  pointer-events: none;
  transition: opacity 0.3s, background 0.3s;
  min-width: 140px;
  text-align: right;
}
#status.hidden {
  opacity: 0;
  pointer-events: none;
}
#status.playing {
  background: rgba(0, 0, 0, 0.6);
  border-color: rgba(74, 222, 128, 0.1);
}
</style>
</head><body>
<div id="container">
  <video id="video" controls autoplay playsinline></video>
</div>
<div id="status">Loading...</div>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.17/dist/hls.min.js"></script>
<script>
const status = document.getElementById('status');
const video = document.getElementById('video');
const src = '/master.m3u8';

if (Hls.isSupported()) {
  const hls = new Hls({
    debug: false,
    progressive: true,
    maxBufferLength: 120,
    maxMaxBufferLength: 600,
    maxBufferSize: 100000000,
    maxBufferHole: 0.1,
    nudgeOffset: 0.1,
    nudgeMaxRetry: 5,
    stretchShortVideoTrack: true,
    backBufferLength: Infinity,
    manifestLoadPolicy: {
      default: {
        maxTimeToFirstByteMs: Infinity,
        maxLoadTimeMs: 20000,
        timeoutRetry: { maxNumRetry: 3, retryDelayMs: 0, maxRetryDelayMs: 0 },
        errorRetry: { maxNumRetry: 8, retryDelayMs: 1000, maxRetryDelayMs: 2000, backoff: 'linear' }
      }
    },
    fragLoadPolicy: {
      default: {
        maxTimeToFirstByteMs: 10000,
        maxLoadTimeMs: 120000,
        timeoutRetry: { maxNumRetry: 4, retryDelayMs: 0, maxRetryDelayMs: 0 },
        errorRetry: { maxNumRetry: 8, retryDelayMs: 1000, maxRetryDelayMs: 2000, backoff: 'linear' }
      }
    },
    playlistLoadPolicy: {
      default: {
        maxTimeToFirstByteMs: 10000,
        maxLoadTimeMs: 20000,
        timeoutRetry: { maxNumRetry: 3, retryDelayMs: 0, maxRetryDelayMs: 0 },
        errorRetry: { maxNumRetry: 8, retryDelayMs: 1000, maxRetryDelayMs: 2000, backoff: 'linear' }
      }
    }
  });

  hls.loadSource(src);
  hls.attachMedia(video);

  let autoHideTimer;
  const hideStatus = () => {
    clearTimeout(autoHideTimer);
    autoHideTimer = setTimeout(() => {
      if (video.paused) return;
      status.classList.add('hidden');
    }, 3000);
  };

  hls.on(Hls.Events.MANIFEST_PARSED, () => {
    status.classList.remove('hidden');
    status.textContent = 'Buffering...';
    video.play().catch(() => {});
  });

  hls.on(Hls.Events.FRAG_LOADED, (e, data) => {
    const buffered = video.buffered;
    if (buffered.length > 0) {
      const ahead = buffered.end(buffered.length - 1) - video.currentTime;
      status.textContent = ahead.toFixed(1) + 's buffer';
      if (ahead > 15) {
        status.classList.add('playing');
        hideStatus();
      } else {
        status.classList.remove('playing');
        status.classList.remove('hidden');
      }
    }
  });

  hls.on(Hls.Events.ERROR, (e, data) => {
    if (data.fatal) {
      status.classList.remove('hidden', 'playing');
      status.textContent = data.type + ' ⟳';
      if (data.type === Hls.ErrorTypes.MEDIA_ERROR) hls.recoverMediaError();
      else { hls.destroy(); hls.loadSource(src); hls.attachMedia(video); }
    }
  });

  video.addEventListener('play', () => {
    status.classList.add('playing');
    hideStatus();
  });
  video.addEventListener('pause', () => {
    clearTimeout(autoHideTimer);
    status.classList.remove('hidden');
  });
  video.addEventListener('waiting', () => {
    status.classList.remove('playing', 'hidden');
    status.textContent = 'Buffering...';
    clearTimeout(autoHideTimer);
  });

} else if (video.canPlayType('application/vnd.apple.mpegurl')) {
  video.src = src;
  video.addEventListener('loadedmetadata', () => { video.play(); });
}

setInterval(() => { fetch('/ping').catch(() => {}); }, 3000);

window.addEventListener('beforeunload', () => {
  navigator.sendBeacon('/close', '');
});
</script>
</body></html>"""
    
    def _rewrite_m3u8(text, base_url, port):
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                if 'URI="' in stripped:
                    def rewrite_uri(match):
                        url = match.group(1)
                        if not url.startswith("http"):
                            url = base_url + url
                        return f'URI="http://127.0.0.1:{port}/proxy?url={quote(url, safe="")}"'
                    lines.append(re.sub(r'URI="([^"]+)"', rewrite_uri, stripped))
                else:
                    lines.append(stripped)
            elif stripped.startswith("http"):
                lines.append(f"http://127.0.0.1:{port}/proxy?url={quote(stripped, safe='')}")
            elif stripped and not stripped.startswith("#"):
                abs_url = base_url + stripped
                lines.append(f"http://127.0.0.1:{port}/proxy?url={quote(abs_url, safe='')}")
            else:
                lines.append(stripped)
        return "\n".join(lines) + "\n"
    
    class ProxyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path
            self.server.last_request_time = time.time()

            if path == "/ping":
                self.send_response(200)
                self.end_headers()
                return

            if path == "/close":
                self.send_response(204)
                self.end_headers()
                self.server.browser_closed = True
                return

            if path == "/" or path == "/player":
                self._send(200, PLAYER_HTML.encode("utf-8"), "text/html")
                return

            if path.startswith("/master"):
                self._send(200, self.server.rewritten_manifest.encode("utf-8"),
                           "application/vnd.apple.mpegurl")
                return

            if path.startswith("/proxy?url="):
                real_url = unquote(path[len("/proxy?url="):])
                
                url_path = real_url.split("?")[0].lower()
                is_manifest = url_path.endswith(".m3u8")
                is_segment = not is_manifest

                if real_url in cache:
                    content, content_type = cache[real_url]
                    self._send(200, content, content_type)
                    return

                result = _fetch_with_token(real_url, "manifest" if is_manifest else "segment")
                if result:
                    content, content_type = result
                    if is_manifest and (b"#EXTM3U" in content[:20] or b"#EXTINF" in content[:5000]):
                        text = content.decode("utf-8", errors="replace")
                        base = real_url.rsplit("/", 1)[0] + "/"
                        if real_url not in playlist_segments:
                            seg_list = []
                            for ln in text.splitlines():
                                sv = ln.strip()
                                if sv and not sv.startswith("#"):
                                    su = sv if sv.startswith("http") else base + sv
                                    seg_list.append(su)
                                    seg_to_playlist[su] = real_url
                                    seg_to_index[su] = len(seg_list) - 1
                            playlist_segments[real_url] = seg_list
                        port = self.server.server_address[1]
                        text = _rewrite_m3u8(text, base, port)
                        content = text.encode("utf-8")
                        content_type = "application/vnd.apple.mpegurl"

                    with cache_lock:
                        cache[real_url] = (content, content_type)
                    self._send(200, content, content_type)
                else:
                    self._send(502, b"Failed", "text/plain")
                return

            self.send_response(404)
            self.end_headers()
        
        def _send(self, status, content, content_type="application/octet-stream"):
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(content if isinstance(content, bytes) else content.encode())
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                pass
        
        def do_POST(self):
            path = self.path
            self.server.last_request_time = time.time()
            if path == "/close":
                self.send_response(204)
                self.end_headers()
                self.server.browser_closed = True
                return
            self.send_response(404)
            self.end_headers()
        
        def log_message(self, format, *args):
            pass
    
    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
    
    server = ThreadedHTTPServer(("127.0.0.1", 0), ProxyHandler)
    port = server.server_address[1]
    server.last_request_time = time.time()
    server.browser_closed = False

    rewritten_lines = []
    for line in trimmed_master.splitlines():
        stripped = line.strip()
        if stripped.startswith("http"):
            rewritten_lines.append(f"http://127.0.0.1:{port}/proxy?url={quote(stripped, safe='')}")
        elif 'URI="' in stripped:
            def rewrite_uri(match):
                url = match.group(1)
                return f'URI="http://127.0.0.1:{port}/proxy?url={quote(url, safe="")}"'
            rewritten_lines.append(re.sub(r'URI="([^"]+)"', rewrite_uri, stripped))
        else:
            rewritten_lines.append(stripped)
    server.rewritten_manifest = "\n".join(rewritten_lines) + "\n"

    for url in list(cache.keys()):
        content, ct = cache[url]
        if ct == "application/vnd.apple.mpegurl" and isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
            if "#EXTM3U" in text[:20] or "#EXTINF" in text[:5000]:
                base = url.rsplit("/", 1)[0] + "/"
                cache[url] = (_rewrite_m3u8(text, base, port).encode("utf-8"), ct)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    player_url = f"http://127.0.0.1:{port}/"
    
    print(f"[*] Player ready at {player_url}")
    webbrowser.open(player_url)

    try:
        while True:
            time.sleep(0.5)
            if server.browser_closed or (time.time() - server.last_request_time > 15):
                print("\n[*] Session ended.")
                break
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        server.shutdown()

def main():
    if len(sys.argv) < 2:
        print("Usage: python anime_nexus_grab.py <episode_id>")
        print("Example: python anime_nexus_grab.py 019b9e8f-edf6-71a7-87c5-c45f64297245")
        sys.exit(1)

    episode_id = sys.argv[1]
    print(f"[*] Episode: {episode_id}")

    fp = generate_fingerprint()
    session = create_session(fp)
    print("[*] Session created")

    headers = get_api_headers(fp)
    data = fetch_stream(session, headers, episode_id)

    if not data:
        print("[!] Failed to fetch stream info")
        sys.exit(1)

    stream_data = data.get("data", data)
    hls_url = stream_data.get("hls")
    if not hls_url:
        print("[!] No HLS URL found")
        sys.exit(1)

    video_id = episode_id
    meta = stream_data.get("video_meta", {})
    subs = stream_data.get("subtitles", [])
    dur = meta.get("duration", "?")
    quals = ", ".join(meta.get("qualities", {}).keys())
    audio = ", ".join(meta.get("audio_languages", []))
    print(f"[*] {dur}s | {quals} | Audio: {audio} | {len(subs)} subs")

    session_cookie = ""
    for name, value in session.cookies.items():
        if name == "anime_nexus_session":
            session_cookie = value
            break

    ts = TokenSystem(video_id, fp, hls_url, session_cookie)
    print("[*] Connecting...")
    if not ts.connect():
        print("[!] Token connection failed")
        sys.exit(1)
    print("[*] Connected")

    master_manifest = fetch_m3u8(session, ts, hls_url)
    if not master_manifest:
        print("[!] Failed to fetch manifest")
        ts.disconnect()
        sys.exit(1)

    play_with_mpv(hls_url, ts, fp, master_manifest, session)

    ts.disconnect()
    print("[*] Done")


if __name__ == "__main__":
    main()