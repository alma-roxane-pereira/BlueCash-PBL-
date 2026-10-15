"""
A public status page at `GET /`.

A deployed mint answers on a URL that someone will eventually open in a
browser, and a bare 404 there reads as a broken service. This serves the few
facts that are already public — the mint fingerprint, the denominations it
issues, and the current audit root — in a form a person can read.

Everything shown here is available from `/mint/keys` and `/audit/root/latest`
already. The page adds presentation, not disclosure.

Three constraints shaped it:

* **Read-only.** No bootstrap, no key generation, no writes. A status page that
  initialised a mint because someone opened it in a browser would be a way to
  create a mint identity by accident.
* **Degrades rather than leaks.** If the database is unreachable the page says
  so and nothing more. An exception trace on a public URL gives away the
  schema, the paths and often the connection string.
* **Self-contained.** No external scripts, fonts or stylesheets. A page that
  phones out to a CDN is a third party watching whoever checks the mint, and
  it would break entirely on a locked-down network.
"""

from __future__ import annotations

import hashlib
from html import escape

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import protocol
from ..config import Settings, get_settings
from ..db.models import MintIdentity, MintKey
from ..db.session import get_session
from .mint import _all_leaves

router = APIRouter(tags=["ops"])

UNAVAILABLE = "unavailable"


def fingerprint(public_key_hex: str) -> str:
    """The mint's short fingerprint.

    `sha256(public_key_hex)[:16]`, the same convention `dev-server.ps1` and
    `dev-server.sh` print, so a fingerprint read here can be compared directly
    with one read from a database file.
    """
    return hashlib.sha256(public_key_hex.encode()).hexdigest()[:16]


def _collect(session: Session) -> dict:
    """Everything the page shows, from one pass over the database.

    Returns `ok=False` with no detail if anything fails. The caller renders a
    degraded page; the exception is deliberately not propagated, because this
    route is public and a 500 page would describe the internals.
    """
    try:
        identity = session.get(MintIdentity, 1)
        keys = list(
            session.scalars(
                select(MintKey).where(MintKey.active.is_(True)).order_by(MintKey.amount)
            ).all()
        )
        leaves = _all_leaves(session)
        return {
            "ok": True,
            # No identity means the database exists but was never bootstrapped.
            # That is a real state, not an error, and it is worth showing.
            "fingerprint": fingerprint(identity.public_key_hex) if identity else None,
            "denominations": [(k.amount, k.currency) for k in keys],
            "root": protocol.merkle_root_hex(leaves),
            "tree_size": len(leaves),
        }
    except Exception:  # noqa: BLE001 - deliberately broad; see the docstring
        return {"ok": False}


def _render(data: dict, settings: Settings) -> str:
    """The page. Values are escaped at the point of interpolation."""
    service = escape(settings.service_name)
    version = escape(settings.version)

    if not data["ok"]:
        state_class, state_label = "bad", "Status unavailable"
        body = (
            '<p class="muted">The mint could not read its own state. '
            "The service is running but cannot answer for itself right now.</p>"
        )
    elif data["fingerprint"] is None:
        state_class, state_label = "warn", "Not initialised"
        body = (
            '<p class="muted">No mint identity has been created in this database yet.</p>'
        )
    else:
        state_class, state_label = "ok", "Operational"

        denominations = data["denominations"]
        if denominations:
            chips = "".join(
                f'<span class="chip">{escape(currency)} {amount:,}</span>'
                for amount, currency in denominations
            )
        else:
            chips = '<span class="muted">none configured</span>'

        tree_size = data["tree_size"]
        if tree_size == 0:
            # An empty log is the correct state for a mint that has issued
            # nothing, so it is stated rather than shown as a blank field.
            audit_value = '<span class="muted">empty &mdash; nothing issued yet</span>'
        else:
            audit_value = (
                f'<code>{escape(data["root"])}</code>'
                f'<div class="muted">{tree_size:,} '
                f'{"leaf" if tree_size == 1 else "leaves"}</div>'
            )

        body = f"""
        <dl>
          <dt>Mint fingerprint</dt>
          <dd><code>{escape(data["fingerprint"])}</code>
              <div class="muted">SHA-256 of the mint's public key, first 16 hex characters.
              Wallets pin this and refuse a mint whose key changes.</div></dd>

          <dt>Denominations</dt>
          <dd>{chips}</dd>

          <dt>Audit root</dt>
          <dd>{audit_value}</dd>
        </dl>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{service} &mdash; status</title>
<meta name="robots" content="noindex">
<style>
  :root {{
    --indigo: #2e2d88;
    --page: #f1f2f6;
    --card: #ffffff;
    --ink: #16162e;
    --muted: #6e6e8a;
    --line: #e2e4ec;
    --ok: #1a7f46;
    --warn: #8a5b00;
    --bad: #b3261e;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --page: #101018; --card: #1b1b26; --ink: #ececf2;
      --muted: #9b9bb0; --line: #2e2e3c; --indigo: #9b93f0;
      --ok: #5fd08a; --warn: #e0b35c; --bad: #f2b8b5;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 16px;
    background: var(--page); color: var(--ink);
    font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  main {{ max-width: 620px; margin: 0 auto; }}
  header {{ margin-bottom: 20px; }}
  h1 {{ margin: 0 0 4px; font-size: 26px; letter-spacing: -0.4px; }}
  .sub {{ color: var(--muted); font-size: 14px; }}
  .card {{
    background: var(--card); border: 1px solid var(--line);
    border-radius: 16px; padding: 20px 22px;
  }}
  .state {{
    display: inline-flex; align-items: center; gap: 8px;
    font-weight: 600; margin-bottom: 18px;
  }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; background: currentColor; }}
  .ok {{ color: var(--ok); }}
  .warn {{ color: var(--warn); }}
  .bad {{ color: var(--bad); }}
  dl {{ margin: 0; }}
  dt {{
    font-size: 12px; letter-spacing: 1px; text-transform: uppercase;
    color: var(--muted); margin-top: 18px;
  }}
  dt:first-child {{ margin-top: 0; }}
  dd {{ margin: 6px 0 0; }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 14px; word-break: break-all;
    background: color-mix(in srgb, var(--indigo) 10%, transparent);
    padding: 2px 6px; border-radius: 6px;
  }}
  .chip {{
    display: inline-block; margin: 0 6px 6px 0; padding: 4px 11px;
    border-radius: 999px; font-size: 14px; font-weight: 600;
    background: color-mix(in srgb, var(--indigo) 12%, transparent);
    color: var(--indigo);
  }}
  .muted {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  footer {{ margin-top: 18px; color: var(--muted); font-size: 12.5px; }}
  footer a {{ color: inherit; }}
</style>
</head>
<body>
<main>
  <header>
    <h1>BlueCash Mint</h1>
    <div class="sub">Offline peer-to-peer digital cash &middot; v{version}</div>
  </header>

  <div class="card">
    <div class="state {state_class}" role="status" aria-label="Service status: {state_label}">
      <span class="dot" aria-hidden="true"></span>{state_label}
    </div>
    {body}
  </div>

  <footer>
    <p>This page reports service status only. It does not certify the
    security of the system, and it is not evidence that any particular
    payment settled.</p>
    <p>Machine-readable: <a href="/health">/health</a>,
       <a href="/mint/keys">/mint/keys</a>,
       <a href="/audit/root/latest">/audit/root/latest</a>.</p>
  </footer>
</main>
</body>
</html>
"""


@router.get(
    "/",
    response_class=HTMLResponse,
    summary="Service status page",
    # Kept out of the schema: it is a page for people, and listing it among
    # the protocol endpoints would suggest it is part of the API contract.
    include_in_schema=False,
)
def status_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    settings = getattr(request.app.state, "settings", None) or get_settings()
    return HTMLResponse(_render(_collect(session), settings))
