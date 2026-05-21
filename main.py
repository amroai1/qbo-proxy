"""
QBO Proxy — per-client QuickBooks Online OAuth + query service.

Endpoints:
  GET  /health
  GET  /debug/{slug}                             (API key — runs CompanyInfo)
  GET  /oauth/start?slug=<>&display_name=<>     (browser, no API key)
  GET  /oauth/callback                          (Intuit redirects here)
  GET  /clients                                 (API key)
  POST /clients/{slug}/vendor-lookup            (API key) body: {display_name}
  POST /clients/{slug}/bills                    (API key) body: {vendor_id, period_start, period_end}

Token refresh is lazy: every query checks expiry, refreshes if within 5 min of expiring,
and retries once on a 401 from QBO.

Verbose structured logging — every meaningful action logs a [TAG] prefixed line to stdout
so Coolify Logs tab shows the full story.
"""

import base64
import logging
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("qbo-proxy")


def mask(s, keep=12):
    """Show first `keep` chars then ellipsis. For sensitive values in logs."""
    if not s:
        return "<empty>"
    if len(s) <= keep:
        return s + "..."
    return s[:keep] + "..."


# ---------- Config ----------
CLIENT_ID = os.environ["QBO_CLIENT_ID"]
CLIENT_SECRET = os.environ["QBO_CLIENT_SECRET"]
QBO_ENV = os.environ.get("QBO_ENV", "production")
DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.environ["PROXY_API_KEY"]
BASE_URL = os.environ["BASE_URL"].rstrip("/")

QBO_API_BASE = (
    "https://quickbooks.api.intuit.com"
    if QBO_ENV == "production"
    else "https://sandbox-quickbooks.api.intuit.com"
)
AUTHORIZE_URL = "https://appcenter.intuit.com/connect/oauth2"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
SCOPE = "com.intuit.quickbooks.accounting"
MINOR_VERSION = "73"

log.info("=" * 70)
log.info("[STARTUP] qbo-proxy booting")
log.info(f"[STARTUP] QBO_ENV          = {QBO_ENV}")
log.info(f"[STARTUP] QBO_API_BASE     = {QBO_API_BASE}")
log.info(f"[STARTUP] BASE_URL         = {BASE_URL}")
log.info(f"[STARTUP] QBO_CLIENT_ID    = {mask(CLIENT_ID)}  (length {len(CLIENT_ID)})")
log.info(f"[STARTUP] QBO_CLIENT_SECRET= {mask(CLIENT_SECRET, 4)}  (length {len(CLIENT_SECRET)})")
log.info(f"[STARTUP] PROXY_API_KEY    = {mask(API_KEY, 8)}  (length {len(API_KEY)})")
log.info(f"[STARTUP] SCOPE            = {SCOPE}")
log.info(f"[STARTUP] AUTHORIZE_URL    = {AUTHORIZE_URL}")
log.info(f"[STARTUP] TOKEN_URL        = {TOKEN_URL}")
log.info(f"[STARTUP] Redirect URI     = {BASE_URL}/oauth/callback")
log.info("=" * 70)

app = FastAPI(title="QBO Proxy")

# In-memory OAuth state. If service restarts mid-OAuth, restart at /oauth/start.
_oauth_state: dict[str, dict] = {}


# ---------- Request logging middleware ----------
@app.middleware("http")
async def request_logger(request: Request, call_next):
    # Skip noise from bot scans and favicon
    path = request.url.path
    is_noise = (
        path in ("/", "/favicon.ico")
        or path.startswith("/.")
        or "swagger" in path
        or "actuator" in path
        or "wp-" in path
        or path.endswith(".php")
    )
    if not is_noise:
        log.info(f"[REQ] {request.method} {path}{'?' + request.url.query if request.url.query else ''}")
    response = await call_next(request)
    if not is_noise:
        log.info(f"[RES] {request.method} {path} -> {response.status_code}")
    return response


# ---------- DB ----------
def db():
    return psycopg.connect(DATABASE_URL, autocommit=True)


def upsert_client(slug, display_name, realm_id, access_token, refresh_token, expires_at):
    log.info(f"[DB] upserting client slug={slug} realm={realm_id} expires_at={expires_at.isoformat()}")
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO clients (slug, display_name, realm_id, access_token, refresh_token, expires_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (slug) DO UPDATE SET
              display_name  = EXCLUDED.display_name,
              realm_id      = EXCLUDED.realm_id,
              access_token  = EXCLUDED.access_token,
              refresh_token = EXCLUDED.refresh_token,
              expires_at    = EXCLUDED.expires_at,
              updated_at    = NOW();
            """,
            (slug, display_name, realm_id, access_token, refresh_token, expires_at),
        )
    log.info(f"[DB] upsert OK slug={slug}")


def get_client(slug):
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT slug, display_name, realm_id, access_token, refresh_token, expires_at FROM clients WHERE slug = %s",
            (slug,),
        )
        row = cur.fetchone()
    if not row:
        log.warning(f"[DB] client lookup failed: slug={slug} not found")
        raise HTTPException(404, f"Client '{slug}' not found. Onboard via /oauth/start first.")
    client = {
        "slug": row[0],
        "display_name": row[1],
        "realm_id": row[2],
        "access_token": row[3],
        "refresh_token": row[4],
        "expires_at": row[5],
    }
    log.info(
        f"[DB] loaded slug={slug} realm={client['realm_id']} "
        f"access_token={mask(client['access_token'], 20)} "
        f"expires_at={client['expires_at'].isoformat()}"
    )
    return client


# ---------- OAuth + token refresh ----------
def basic_auth_header():
    raw = f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def refresh_tokens(client):
    log.info(f"[REFRESH] refreshing tokens for slug={client['slug']}")
    r = httpx.post(
        TOKEN_URL,
        headers={
            "Authorization": basic_auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "refresh_token", "refresh_token": client["refresh_token"]},
        timeout=30,
    )
    log.info(f"[REFRESH] response status={r.status_code}")
    if r.status_code != 200:
        log.error(f"[REFRESH] FAILED body={r.text}")
        raise HTTPException(502, f"Token refresh failed: {r.status_code} {r.text}")
    body = r.json()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body["expires_in"] - 60)
    log.info(
        f"[REFRESH] OK new_access={mask(body['access_token'], 20)} "
        f"expires_in={body['expires_in']}s new_expires_at={expires_at.isoformat()}"
    )
    upsert_client(
        client["slug"],
        client["display_name"],
        client["realm_id"],
        body["access_token"],
        body["refresh_token"],
        expires_at,
    )
    client["access_token"] = body["access_token"]
    client["refresh_token"] = body["refresh_token"]
    client["expires_at"] = expires_at
    return client


def fresh_client(slug):
    client = get_client(slug)
    now = datetime.now(timezone.utc)
    if client["expires_at"] <= now + timedelta(minutes=5):
        log.info(f"[REFRESH] token expiring soon (now={now.isoformat()} expires={client['expires_at'].isoformat()}), refreshing")
        client = refresh_tokens(client)
    else:
        log.info(f"[REFRESH] token still fresh, skipping refresh (expires={client['expires_at'].isoformat()})")
    return client


def qbo_query(client, query):
    url = f"{QBO_API_BASE}/v3/company/{client['realm_id']}/query"
    headers = {"Authorization": f"Bearer {client['access_token']}", "Accept": "application/json"}
    params = {"query": query, "minorversion": MINOR_VERSION}
    log.info(f"[QBO] GET {url}")
    log.info(f"[QBO] query={query}")
    log.info(f"[QBO] auth=Bearer {mask(client['access_token'], 20)}")
    r = httpx.get(url, params=params, headers=headers, timeout=60)
    log.info(f"[QBO] response status={r.status_code} body_length={len(r.text)}")
    if r.status_code == 401:
        log.warning(f"[QBO] 401 received, attempting one-shot refresh+retry")
        log.warning(f"[QBO] 401 body={r.text}")
        client = refresh_tokens(client)
        headers["Authorization"] = f"Bearer {client['access_token']}"
        r = httpx.get(url, params=params, headers=headers, timeout=60)
        log.info(f"[QBO] retry status={r.status_code}")
    if r.status_code != 200:
        log.error(f"[QBO] FAILED status={r.status_code} body={r.text}")
        raise HTTPException(502, f"QBO error {r.status_code}: {r.text}")
    log.info(f"[QBO] success")
    return r.json()


# ---------- API key guard for n8n-facing endpoints ----------
def require_api_key(x_api_key: str | None = Header(default=None)):
    if x_api_key != API_KEY:
        log.warning(f"[AUTH] rejected — got X-API-Key={mask(x_api_key or '', 8)}")
        raise HTTPException(401, "Invalid or missing X-API-Key header")


# ---------- Public endpoints ----------
@app.get("/health")
def health():
    return {
        "ok": True,
        "qbo_env": QBO_ENV,
        "qbo_api_base": QBO_API_BASE,
        "client_id_prefix": CLIENT_ID[:12] + "...",
        "base_url": BASE_URL,
        "redirect_uri": f"{BASE_URL}/oauth/callback",
    }


@app.get("/debug/{slug}", dependencies=[Depends(require_api_key)])
def debug_client(slug: str):
    """Hits QBO's CompanyInfo endpoint — the simplest possible authenticated call.
    Returns the raw response so we can see exactly what Intuit says."""
    log.info(f"[DEBUG] CompanyInfo probe for slug={slug}")
    client = fresh_client(slug)
    url = f"{QBO_API_BASE}/v3/company/{client['realm_id']}/companyinfo/{client['realm_id']}"
    headers = {
        "Authorization": f"Bearer {client['access_token']}",
        "Accept": "application/json",
    }
    log.info(f"[DEBUG] GET {url}")
    log.info(f"[DEBUG] auth=Bearer {mask(client['access_token'], 20)}")
    r = httpx.get(url, params={"minorversion": MINOR_VERSION}, headers=headers, timeout=30)
    log.info(f"[DEBUG] response status={r.status_code}")
    log.info(f"[DEBUG] response body={r.text}")
    return {
        "qbo_api_base": QBO_API_BASE,
        "realm_id": client["realm_id"],
        "token_expires_at": client["expires_at"].isoformat(),
        "access_token_prefix": client["access_token"][:20] + "...",
        "qbo_status": r.status_code,
        "qbo_body": r.text,
    }


@app.get("/oauth/start")
def oauth_start(slug: str = Query(...), display_name: str = Query(...)):
    state = secrets.token_urlsafe(32)
    _oauth_state[state] = {"slug": slug, "display_name": display_name}
    redirect_uri = f"{BASE_URL}/oauth/callback"
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPE,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    auth_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    log.info(f"[OAUTH] start slug={slug} display_name={display_name}")
    log.info(f"[OAUTH] redirect_uri sent to Intuit: {redirect_uri}")
    log.info(f"[OAUTH] client_id sent to Intuit: {mask(CLIENT_ID)}")
    log.info(f"[OAUTH] redirecting browser to Intuit authorize URL")
    return RedirectResponse(auth_url)


@app.get("/oauth/callback")
def oauth_callback(code: str, realmId: str, state: str):
    log.info(f"[OAUTH] callback received realmId={realmId} code={mask(code, 12)}")
    pending = _oauth_state.pop(state, None)
    if not pending:
        log.error(f"[OAUTH] unknown state — possible stale or replay")
        raise HTTPException(400, "Unknown or expired OAuth state. Restart at /oauth/start.")
    log.info(f"[OAUTH] matched pending state slug={pending['slug']} display_name={pending['display_name']}")
    redirect_uri = f"{BASE_URL}/oauth/callback"
    log.info(f"[OAUTH] exchanging code for tokens, redirect_uri={redirect_uri}")
    r = httpx.post(
        TOKEN_URL,
        headers={
            "Authorization": basic_auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        },
        timeout=30,
    )
    log.info(f"[OAUTH] token exchange status={r.status_code}")
    if r.status_code != 200:
        log.error(f"[OAUTH] token exchange FAILED body={r.text}")
        raise HTTPException(502, f"Token exchange failed: {r.status_code} {r.text}")
    body = r.json()
    log.info(
        f"[OAUTH] tokens issued access={mask(body['access_token'], 20)} "
        f"refresh={mask(body['refresh_token'], 12)} expires_in={body['expires_in']}s "
        f"token_type={body.get('token_type')} x_refresh_in={body.get('x_refresh_token_expires_in')}s"
    )
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body["expires_in"] - 60)
    upsert_client(
        slug=pending["slug"],
        display_name=pending["display_name"],
        realm_id=realmId,
        access_token=body["access_token"],
        refresh_token=body["refresh_token"],
        expires_at=expires_at,
    )
    log.info(f"[OAUTH] onboarding complete for slug={pending['slug']}")
    return HTMLResponse(
        f"<h2>Connected: {pending['display_name']}</h2>"
        f"<p>Slug: <code>{pending['slug']}</code><br/>Realm: <code>{realmId}</code></p>"
        f"<p>You can close this tab.</p>"
    )


# ---------- API-key-protected endpoints ----------
@app.get("/clients", dependencies=[Depends(require_api_key)])
def list_clients():
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT slug, display_name, realm_id, expires_at, updated_at FROM clients ORDER BY slug"
        )
        rows = cur.fetchall()
    log.info(f"[CLIENTS] listed {len(rows)} clients")
    return [
        {
            "slug": r[0],
            "display_name": r[1],
            "realm_id": r[2],
            "expires_at": r[3].isoformat(),
            "updated_at": r[4].isoformat(),
        }
        for r in rows
    ]


class VendorLookupBody(BaseModel):
    display_name: str


@app.post("/clients/{slug}/vendor-lookup", dependencies=[Depends(require_api_key)])
def vendor_lookup(slug: str, body: VendorLookupBody):
    log.info(f"[VENDOR] lookup slug={slug} display_name={body.display_name!r}")
    # QBO's query language has no working escape for apostrophes inside string
    # literals — neither \' nor '' parses correctly. Replace apostrophes with %
    # (LIKE wildcard) so "The Chefs' Warehouse" still matches.
    name = body.display_name.split("(")[0].strip().replace("'", "%")
    query = f"SELECT * FROM Vendor WHERE DisplayName LIKE '%{name}%'"
    res = qbo_query(fresh_client(slug), query)
    vendors = res.get("QueryResponse", {}).get("Vendor", [])
    log.info(f"[VENDOR] match_count={len(vendors)}")
    if not vendors:
        raise HTTPException(404, f"No vendor matching '{body.display_name}'")
    return {"vendors": vendors, "match_count": len(vendors)}


@app.get("/clients/{slug}/vendors-active", dependencies=[Depends(require_api_key)])
def vendors_active(slug: str):
    """Returns vendors with open balance > 0, sorted by balance descending.
    This is the live AP universe — vendors we currently owe."""
    log.info(f"[VENDORS-ACTIVE] slug={slug}")
    # QBO Vendor query language doesn't support range/!=  operators on numeric Balance
    # (only on boolean fields). Fetch all vendors, paginate, filter to Balance > 0 in Python.
    client = fresh_client(slug)
    all_vendors: list[dict] = []
    page_size = 1000
    start = 1
    while True:
        query = f"SELECT * FROM Vendor STARTPOSITION {start} MAXRESULTS {page_size}"
        res = qbo_query(client, query)
        batch = res.get("QueryResponse", {}).get("Vendor", [])
        all_vendors.extend(batch)
        if len(batch) < page_size:
            break
        start += page_size
    log.info(f"[VENDORS-ACTIVE] fetched {len(all_vendors)} total vendors")
    vendors = [v for v in all_vendors if float(v.get("Balance") or 0) > 0]
    vendors.sort(key=lambda v: float(v.get("Balance") or 0), reverse=True)
    log.info(f"[VENDORS-ACTIVE] count={len(vendors)}")
    return {
        "count": len(vendors),
        "vendors": [
            {
                "Id": v.get("Id"),
                "DisplayName": v.get("DisplayName"),
                "Balance": v.get("Balance"),
                "Active": v.get("Active"),
            }
            for v in vendors
        ],
    }


class BillsBody(BaseModel):
    vendor_id: str
    period_start: str | None = None
    period_end: str | None = None


@app.post("/clients/{slug}/bills", dependencies=[Depends(require_api_key)])
def fetch_bills(slug: str, body: BillsBody):
    log.info(
        f"[BILLS] fetch slug={slug} vendor_id={body.vendor_id} "
        f"period={body.period_start or 'open'}..{body.period_end or 'open'}"
    )
    where = [f"VendorRef = '{body.vendor_id}'"]
    if body.period_start:
        where.append(f"TxnDate >= '{body.period_start}'")
    if body.period_end:
        where.append(f"TxnDate <= '{body.period_end}'")
    query = "SELECT * FROM Bill WHERE " + " AND ".join(where) + " MAXRESULTS 1000"
    res = qbo_query(fresh_client(slug), query)
    bills = res.get("QueryResponse", {}).get("Bill", [])
    log.info(f"[BILLS] count={len(bills)}")
    return {"bills": bills, "count": len(bills)}
