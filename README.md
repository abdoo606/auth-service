# 13 · authsvc

Password hashing and JWTs built from primitives - zero crypto dependencies.

## Run

```bash
from authsvc.jwtsvc import JWTService
```

## Test

```bash
pytest projects/13-auth-service -q
```

## What it demonstrates

- PBKDF2-HMAC-SHA256, 260k iterations, per-user salt, parameters encoded in the hash
- HS256 JWT with `alg: none` rejection, issuer check and `exp` enforcement
- Refresh-token rotation with reuse detection: replay revokes the whole family
- `hmac.compare_digest` everywhere a secret is compared
