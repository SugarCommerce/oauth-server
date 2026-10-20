# OAuth Server

The authorization-server half of OAuth 2.1, profiled for a remote **MCP server** that is its own authorization server: so somebody can add your server to Claude or ChatGPT by clicking "Connect", signing in, and approving — no pasted token.

Follows the MCP authorization specification, revision **2026-07-28**, which profiles OAuth 2.1 (draft-ietf-oauth-v2-1-13), RFC 8414, RFC 9728, RFC 8707, RFC 9207, RFC 7591, RFC 7009 and Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00).

`sugarcommerce/oauth` is the other half — the client's PKCE pair and browser-bound state.

## Why

An MCP client meeting your server for the first time has no client id, no secret and no relationship with you. The spec's answer is a stack of RFCs, each of which has a classic mistake:

- **The authorization endpoint becomes an open redirector** when it redirects an error before the client and redirect URI are known good.
- **Redirect URIs are matched by prefix**, or `https://good.example@evil.example/` is read as good.
- **PKCE is optional, or `plain` is accepted** — which sends the verifier through the browser.
- **Tokens are not bound to an audience**, so a token minted for one server is accepted by another.
- **Refresh tokens are long-lived bearer values with no reuse detection**, so a stolen one works for ever alongside the real one.
- **The client's metadata document is fetched without an SSRF guard**, and the client id is a URL a stranger chose.

## What it does

- 📄 **Metadata** — RFC 9728 protected resource metadata and RFC 8414 authorization server metadata from one `Settings`, so what is advertised is what is enforced.
- 🪪 **Clients** — Client ID Metadata Documents (fetched with the SSRF policy on, no redirects, 5 KB, cached within 5 minutes and a day) and RFC 7591 dynamic registration. Always public clients (`none`), which is what Claude, ChatGPT and Claude Code use.
- 🔐 **Authorization code + PKCE S256 only**, exact redirect URIs (any port on loopback, OAuth 2.1 §8.4.2), `state` passed through, `iss` on every response (RFC 9207).
- 🎯 **Resource indicators** — a request for another resource is `invalid_target`; every token is bound to the resource and `authenticate()` refuses one bound to another.
- 🔁 **Rotating refresh tokens with reuse detection** — a spent refresh token, or a code, presented twice revokes the whole grant.
- 🧾 **Opaque tokens stored as SHA-256 digests**, short-lived access tokens (an hour by default), prefixed so a leaked one is recognisable.
- 🚫 **Revocation** (RFC 7009) — a refresh token takes its grant with it; the answer never says whether a token existed.
- 🪜 **Scope hierarchies** — `write` implies `read`, expanded once, at issue.

## Requirements

PHP 8.5+, `ext-mbstring`, [`sugarcommerce/oauth`](https://github.com/sugarcommerce/oauth) (PKCE), [`sugarcommerce/generate`](https://github.com/sugarcommerce/generate) (tokens), [`sugarcommerce/http-client`](https://github.com/sugarcommerce/http-client) (metadata documents).

## Installation

```bash
composer require sugarcommerce/oauth-server
```

## Usage

```php
use SugarCommerce\OAuthServer\{AuthorizationRequest, AuthorizationServer, ClientDocuments, Settings};

$settings = new Settings(
    issuer: 'https://api.example.com',
    resource: 'https://api.example.com/mcp',
    authorization_endpoint: 'https://app.example.com/oauth/authorize',
    token_endpoint: 'https://api.example.com/oauth/token',
    revocation_endpoint: 'https://api.example.com/oauth/revoke',
    registration_endpoint: 'https://api.example.com/oauth/register',
    scopes: [ 'shop:read' => [], 'shop:write' => [ 'shop:read' ] ],
    resource_name: 'Example Shop',
);

$server = new AuthorizationServer( $settings, new MyStore(), new ClientDocuments() );
```

### The two discovery documents

```php
// GET /.well-known/oauth-protected-resource/mcp (and /.well-known/oauth-protected-resource)
json_encode( $settings->resource_metadata() );

// GET /.well-known/oauth-authorization-server
json_encode( $settings->server_metadata() );
```

Send both with `Access-Control-Allow-Origin: *`: browser-based clients read them. An unauthenticated MCP request answers 401 with `WWW-Authenticate: Bearer resource_metadata="<$settings->resource_metadata_url()>"` — `sugarcommerce/mcp-server`'s `Http::headers()` writes it.

### The consent screen

```php
$request = $server->authorize( $_GET );

if ( $request instanceof OAuthError ) {
    $url = $server->error_url( $_GET, $request );
    // null: show $request->description to the person. Never redirect it.
}

// Not signed in? Sign them in first, keeping the query.
// Show: $request->client->name, $request->redirect_host(), $request->scopes,
// and a warning when $request->client->local_only().
// The form posts $request->params back, plus a CSRF token.

// On Approve (after checking CSRF, and re-running authorize() on the posted params):
redirect( $server->approve( $request, $user_id, $approved_scopes, [ 'tenant' => $tenant ] ) );

// On Deny:
redirect( $server->deny( $request ) );
```

Never approve without the person pressing a button.

### Token, revocation and registration endpoints

```php
$reply = $server->token( $_POST );        // application/x-www-form-urlencoded
$reply = $server->revoke( $_POST );
$reply = $server->register( json_decode( $body, true ) ?? [] );

http_response_code( $reply->status );
foreach ( $reply->headers() as $name => $value ) header( "$name: $value" );
echo $reply->json();
```

Rate-limit all three, and the authorization endpoint (it may fetch a URL).

### The resource server

```php
$who = $server->authenticate( $bearer );   // null, or [ 'grant' => Grant, 'scopes' => [...] ]
```

### Storage

Implement `Store`. Two methods must be atomic — `spend_code()` and `spend_refresh()` — because each is what stops a stolen credential being used twice by two racing requests: one conditional `UPDATE … WHERE spent_at IS NULL`, and the affected-row count is the answer. `revoke_grant()` must end every token of the grant. `tests/MemoryStore.php` is the contract in arrays.

## What it does not do

- **Confidential clients, client secrets, `private_key_jwt`.** Every client is public. A metadata document naming `private_key_jwt` is treated as `none`; one naming a shared secret is refused.
- **OpenID Connect.** No id tokens, no `openid-configuration`.
- **Sign the person in, or decide anything for them.** That is your consent screen.
- **Rate limits.** Pair with [`sugarcommerce/rate-limit`](https://github.com/sugarcommerce/rate-limit).

## Testing

```bash
composer install
composer test
```

102 tests — canonical resource URIs, redirect URI rules and loopback ports, well-known paths, registration and metadata-document validation (Claude's and ChatGPT's real documents), the SSRF-guarded fetch and its cache, both metadata documents, the full code + PKCE flow, plain and missing PKCE, redirect and client mismatches never redirected, wrong verifier, expired and replayed codes, other-resource tokens refused, refresh rotation, reuse revoking the grant, scope narrowing, revocation, and registration.

## License

GPL-2.0-or-later
