# Keycloak (local dev)

Issuer is pinned to `http://keycloak:8080/realms/proteus` in `docker-compose.yml`.

Recommended (deterministic issuer): mint tokens inside the compose network so `iss` matches `http://keycloak:8080/realms/proteus`.

If you changed `realm.json`, reset the Keycloak volume so the realm is re-imported:

```sh
podman compose down -v
podman compose up -d keycloak
```

Issuer check:

```sh
podman compose exec keycloak \
  curl -s http://keycloak:8080/realms/proteus/.well-known/openid-configuration | jq -r .issuer
```

Token mint (client credentials):

```sh
TOKEN=$(podman compose exec keycloak sh -lc 'curl -s \
  -d "client_id=proteus-api" \
  -d "client_secret=proteus-secret" \
  -d "grant_type=client_credentials" \
  http://keycloak:8080/realms/proteus/protocol/openid-connect/token | jq -r .access_token')
```

Validate issuer in token:

```sh
TOKEN="$TOKEN" python3 - <<'PY'
import base64, json, os
t=os.environ["TOKEN"].split(".")[1]
pad="=" * (-len(t) % 4)
print(json.loads(base64.urlsafe_b64decode(t+pad)))
PY
```

Example record call (token from above):

```sh
curl -s \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @/path/to/envelope.json \
  http://localhost:8080/v1/manifests:record
```

Expected: HTTP 200 with a receipt payload. If you get `SIGNATURE_INVALID`, re-import the realm and reset the DB:

```sh
podman compose down -v
podman compose up -d
```

## Security notes

- Bearer tokens and raw JWT claims are never logged by `trustd`.
