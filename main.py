"""
QBO Proxy — per-client QuickBooks Online OAuth + query service.

Endpoints:
  GET  /health
  GET  /oauth/start?slug=<>&display_name=<>     (browser, no API key)
  GET  /oauth/callback                          (Intuit redirects here)
  GET  /clients                                 (API key)
  POST /clients/{slug}/vendor-lookup            (API key) body: {display_name}
  POST /clients/{slug}/bills                    (API key) body: {vendor_id, period_start, period_end}

Token refresh is lazy: every query checks expiry, refreshes if within 5 min of expiring,
and retries once on a 401 from QBO.
"""

import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

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

app = FastAPI(title="QBO Proxy")

# In-memory OAuth state. If service restarts mid-OAuth, restart at /oauth/start.
_oauth_state: dict[str, dict] = {}


# ---------- DB ----------
def db():
    return psycopg.connect(DATABASE_URL, autocommit=True)


def upsert_client(slug, display_name, realm_id, access_token, refresh_token, expires_at):
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


def get_client(slug):
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT slug, display_name, realm_id, access_token, refresh_token, expires_at FROM clients WHERE slug = %s",
            (slug,),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, f"Client '{slug}' not found. Onboard via /oauth/start first.")
    return {
        "slug": row[0],
        "display_name": row[1],
        "realm_id": row[2],
        "access_token": row[3],
        "refresh_token": row[4],
        "expires_at": row[5],
    }


# ---------- OAuth + token refresh ----------
def basic_auth_header():
    raw = f"{CLIENT_ID}:{CLIENT_SECRET}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def refresh_tokens(client):
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
    if r.status_code != 200:
        raise HTTPException(502, f"Token refresh failed: {r.status_code} {r.text}")
    body = r.json()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body["expires_in"] - 60)
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
    if client["expires_at"] <= datetime.now(timezone.utc) + timedelta(minutes=5):
        client = refresh_tokens(client)
    return client


def qbo_query(client, query):
    url = f"{QBO_API_BASE}/v3/company/{client['realm_id']}/query"
    headers = {"Authorization": f"Bearer {client['access_token']}", "Accept": "application/json"}
    params = {"query": query, "minorversion": MINOR_VERSION}
    r = httpx.get(url, params=params, headers=headers, timeout=60)
    if r.status_code == 401:
        client = refresh_tokens(client)
        headers["Authorization"] = f"Bearer {client['access_token']}"
        r = httpx.get(url, params=params, headers=headers, timeout=60)
    if r.status_code != 200:
        raise HTTPException(502, f"QBO error {r.status_code}: {r.text}")
    return r.json()


# ---------- API key guard for n8n-facing endpoints ----------
def require_api_key(x_api_key: str | None = Header(default=None)):
    if x_api_key != API_KEY:
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
    }


@app.get("/debug/{slug}", dependencies=[Depends(require_api_key)])
def debug_client(slug: str):
    """Hits QBO's CompanyInfo endpoint — the simplest possible authenticated call.
    Returns the raw response so we can see exactly what Intuit says."""
    client = fresh_client(slug)
    url = f"{QBO_API_BASE}/v3/company/{client['realm_id']}/companyinfo/{client['realm_id']}"
    headers = {
        "Authorization": f"Bearer {client['access_token']}",
        "Accept": "application/json",
    }
    r = httpx.get(url, params={"minorversion": MINOR_VERSION}, headers=headers, timeout=30)
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
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPE,
        "redirect_uri": f"{BASE_URL}/oauth/callback",
        "state": state,
    }
    return RedirectResponse(f"{AUTHORIZE_URL}?{urlencode(params)}")


@app.get("/oauth/callback")
def oauth_callback(code: str, realmId: str, state: str):
    pending = _oauth_state.pop(state, None)
    if not pending:
        raise HTTPException(400, "Unknown or expired OAuth state. Restart at /oauth/start.")
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
            "redirect_uri": f"{BASE_URL}/oauth/callback",
        },
        timeout=30,
    )
    if r.status_code != 200:
        raise HTTPException(502, f"Token exchange failed: {r.status_code} {r.text}")
    body = r.json()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body["expires_in"] - 60)
    upsert_client(
        slug=pending["slug"],
        display_name=pending["display_name"],
        realm_id=realmId,
        access_token=body["access_token"],
        refresh_token=body["refresh_token"],
        expires_at=expires_at,
    )
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
    # Strip parenthetical suffixes like "(ACH)" and escape apostrophes for QBO query
    name = body.display_name.split("(")[0].strip().replace("'", "\\'")
    query = f"SELECT * FROM Vendor WHERE DisplayName LIKE '%{name}%'"
    res = qbo_query(fresh_client(slug), query)
    vendors = res.get("QueryResponse", {}).get("Vendor", [])
    if not vendors:
        raise HTTPException(404, f"No vendor matching '{body.display_name}'")
    return {"vendors": vendors, "match_count": len(vendors)}


class BillsBody(BaseModel):
    vendor_id: str
    period_start: str
    period_end: str


@app.post("/clients/{slug}/bills", dependencies=[Depends(require_api_key)])
def fetch_bills(slug: str, body: BillsBody):
    query = (
        f"SELECT * FROM Bill "
        f"WHERE VendorRef = '{body.vendor_id}' "
        f"AND TxnDate >= '{body.period_start}' "
        f"AND TxnDate <= '{body.period_end}' "
        f"MAXRESULTS 1000"
    )
    res = qbo_query(fresh_client(slug), query)
    bills = res.get("QueryResponse", {}).get("Bill", [])
    return {"bills": bills, "count": len(bills)}
