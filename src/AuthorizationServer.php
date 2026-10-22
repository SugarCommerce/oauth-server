<?php
/**
 * An OAuth 2.1 authorization server for one protected resource.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

use SugarCommerce\Generate\Token;
use SugarCommerce\OAuth\Pkce;

/**
 * Class AuthorizationServer
 *
 * The protocol, following the MCP authorization specification, revision
 * **2026-07-28** (modelcontextprotocol.io/specification/2026-07-28/basic/
 * authorization), which profiles OAuth 2.1 (draft-ietf-oauth-v2-1-13), RFC
 * 8414, RFC 9728, RFC 8707, RFC 9207, RFC 7591, RFC 7009 and Client ID
 * Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00).
 *
 * What it decides, so the application does not have to:
 *
 * - **Authorization code with PKCE, S256 only.** A request with no
 *   challenge, or `plain` (or no method, which RFC 7636 reads as plain), is
 *   refused: plain sends the verifier through the browser and protects
 *   nothing.
 * - **Exact redirect URIs**, the loopback port aside. Until the client and
 *   redirect URI check out, errors are shown, never redirected.
 * - **Resource indicators.** A request for any resource but ours is
 *   `invalid_target`; the grant, and so every token, is bound to the
 *   resource, and authenticate() refuses a token bound to another. A
 *   client that sends no `resource` gets ours — the only one there is.
 * - **`iss` on every authorization response** (RFC 9207), errors included.
 * - **Single-use codes.** A code presented twice revokes the grant it made
 *   (OAuth 2.1 §4.1.3): the second presenter is one of the two parties and
 *   we cannot tell which.
 * - **Rotating refresh tokens with reuse detection** (OAuth 2.1 §4.3.1,
 *   required by MCP for public clients). Each use spends the token and
 *   returns a new one; a spent one presented again revokes the whole grant.
 * - **Short-lived opaque access tokens**, stored as digests.
 *
 * What it leaves to the application: who the person is and whether they
 * approved (the consent screen), rate limits, and the tables (Store).
 *
 * @since 1.0.0
 */
final readonly class AuthorizationServer {

	/**
	 * Clock: returns the current Unix time.
	 *
	 * @var \Closure(): int
	 */
	private \Closure $clock;

	/**
	 * Set up a server over the application's store.
	 *
	 * @since 1.0.0
	 *
	 * @param Settings              $settings  Where and what.
	 * @param Store                 $store     The application's tables.
	 * @param ClientDocuments|null  $documents Fetches metadata documents; null
	 *                                         accepts registered clients only.
	 * @param (\Closure(): int)|null $clock   fn(): int, for tests.
	 */
	public function __construct(
		public Settings $settings,
		private Store $store,
		private ?ClientDocuments $documents = null,
		?\Closure $clock = null,
	) {
		$this->clock = $clock ?? static fn (): int => time();
	}

	/* ─── The authorization endpoint ────────────────────────────────── */

	/**
	 * Check an authorization request.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $params The query (or the consent form's
	 *                                     copy of it).
	 *
	 * @return AuthorizationRequest|OAuthError An error with `redirect` false
	 *                                         is for the person, not the client.
	 */
	public function authorize( array $params ): AuthorizationRequest|OAuthError {
		$params = array_map( static fn ( mixed $value ): string => is_string( $value ) ? $value : '', $params );

		$client = $this->client( $params['client_id'] ?? '' );

		if ( $client instanceof OAuthError ) {
			return $client;
		}

		$redirect = $params['redirect_uri'] ?? '';

		// Required even with one registered URI: the token request must
		// repeat it, and a request that left it out could not.
		if ( '' === $redirect || ! $client->allows_redirect( $redirect ) ) {
			return new OAuthError( 'invalid_request', 'The redirect_uri is missing or is not one this client registered.' );
		}

		// From here on, errors go back to the client.
		if ( 'code' !== ( $params['response_type'] ?? '' ) ) {
			return new OAuthError( 'unsupported_response_type', 'Only response_type=code is supported.', redirect: true );
		}

		$challenge = $params['code_challenge'] ?? '';

		if ( 1 !== preg_match( '/^[A-Za-z0-9\-._~]{43,128}$/', $challenge ) ) {
			return new OAuthError( 'invalid_request', 'A PKCE code_challenge is required.', redirect: true );
		}

		if ( Pkce::METHOD !== ( $params['code_challenge_method'] ?? '' ) ) {
			return new OAuthError( 'invalid_request', 'code_challenge_method must be S256; plain is not accepted.', redirect: true );
		}

		$resource = $this->resource( $params['resource'] ?? '' );

		if ( null === $resource ) {
			return new OAuthError( 'invalid_target', 'This server issues tokens only for ' . $this->settings->resource . '.', redirect: true );
		}

		$scopes = $this->settings->expand( $params['scope'] ?? '' );

		return new AuthorizationRequest(
			client: $client,
			redirect_uri: $redirect,
			state: $params['state'] ?? '',
			challenge: $challenge,
			resource: $resource,
			scopes: array() === $scopes ? $this->settings->scope_names() : $scopes,
			params: array_intersect_key( $params, array_flip( array( 'client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'resource', 'scope', 'state' ) ) ),
		);
	}

	/**
	 * The person approved: where to send the browser, with a code.
	 *
	 * @since 1.0.0
	 *
	 * @param AuthorizationRequest  $request A checked request.
	 * @param string                $subject Who approved.
	 * @param string[]              $scopes  What they approved; anything not
	 *                                       in the settings is dropped.
	 * @param array<string, string> $context Attached to the grant.
	 *
	 * @return string The redirect URL.
	 */
	public function approve( AuthorizationRequest $request, string $subject, array $scopes, array $context = array() ): string {
		$code = Token::url_safe( 32 );
		$now  = $this->now();

		$this->store->save_code( Token::digest( $code ), new Code(
			client_id: $request->client->id,
			redirect_uri: $request->redirect_uri,
			challenge: $request->challenge,
			resource: $request->resource,
			scopes: $this->settings->expand( $scopes ),
			subject: $subject,
			context: $context,
			expires_at: $now + $this->settings->code_ttl,
		) );

		return Uri::with_query( $request->redirect_uri, array( 'code' => $code, 'state' => $request->state, 'iss' => $this->settings->issuer ) );
	}

	/**
	 * The person said no: where to send the browser.
	 *
	 * @since 1.0.0
	 *
	 * @param AuthorizationRequest $request A checked request.
	 *
	 * @return string
	 */
	public function deny( AuthorizationRequest $request ): string {
		return $this->redirect_error( $request->redirect_uri, $request->state, new OAuthError( 'access_denied', 'The person declined.', redirect: true ) );
	}

	/**
	 * Where to send a redirectable error.
	 *
	 * Only for an error with `redirect` true, whose request got as far as a
	 * known client and redirect URI.
	 *
	 * Given the raw query, the client and redirect URI in it are checked
	 * again rather than trusted because the error says it may redirect: an
	 * error from one request paired with another request's query would
	 * otherwise make this an open redirector.
	 *
	 * @since 1.0.0
	 *
	 * @param AuthorizationRequest|array<string, mixed> $request A checked
	 *                                       request, or the raw query when
	 *                                       authorize() returned the error.
	 * @param OAuthError                     $error   The error.
	 *
	 * @return string|null Null when the error must not be redirected.
	 */
	public function error_url( AuthorizationRequest|array $request, OAuthError $error ): ?string {
		if ( ! $error->redirect ) {
			return null;
		}

		if ( $request instanceof AuthorizationRequest ) {
			return $this->redirect_error( $request->redirect_uri, $request->state, $error );
		}

		$client_id = is_string( $request['client_id'] ?? null ) ? $request['client_id'] : '';
		$redirect  = is_string( $request['redirect_uri'] ?? null ) ? $request['redirect_uri'] : '';
		$state     = is_string( $request['state'] ?? null ) ? $request['state'] : '';
		$client    = $this->client( $client_id );

		if ( $client instanceof OAuthError || '' === $redirect || ! $client->allows_redirect( $redirect ) ) {
			return null;
		}

		return $this->redirect_error( $redirect, $state, $error );
	}

	/**
	 * An error sent back to a redirect URI already known to be the client's.
	 *
	 * @param string     $redirect The checked redirect URI.
	 * @param string     $state    The request's state; '' when absent.
	 * @param OAuthError $error    The error.
	 *
	 * @return string
	 */
	private function redirect_error( string $redirect, string $state, OAuthError $error ): string {
		return Uri::with_query( $redirect, array(
			'error'             => $error->error,
			'error_description' => $error->description,
			'state'             => $state,
			'iss'               => $this->settings->issuer,
		) );
	}

	/* ─── The token endpoint ────────────────────────────────────────── */

	/**
	 * Answer a token request.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $form The form-encoded body.
	 *
	 * @return Reply
	 */
	public function token( array $form ): Reply {
		$form = array_map( static fn ( mixed $value ): string => is_string( $value ) ? $value : '', $form );

		$client_id = $form['client_id'] ?? '';

		// A public client identifies itself in the body (OAuth 2.1 §3.2.1).
		if ( '' === $client_id ) {
			return new OAuthError( 'invalid_client', 'client_id is required.', 401 )->reply();
		}

		return match ( $form['grant_type'] ?? '' ) {
			'authorization_code' => $this->exchange_code( $form, $client_id ),
			'refresh_token'      => $this->refresh( $form, $client_id ),
			default              => new OAuthError( 'unsupported_grant_type', 'grant_type is authorization_code or refresh_token.' )->reply(),
		};
	}

	/**
	 * Exchange a code for tokens.
	 *
	 * The code is spent before anything else is checked, so a wrong
	 * verifier burns it: a code is one attempt, not a guessing game.
	 *
	 * @param array<string, string> $form      The body.
	 * @param string                $client_id The caller.
	 *
	 * @return Reply
	 */
	private function exchange_code( array $form, string $client_id ): Reply {
		$hash = Token::digest( $form['code'] ?? '' );
		$now  = $this->now();
		$code = '' === ( $form['code'] ?? '' ) ? null : $this->store->spend_code( $hash, $now );

		if ( null === $code ) {
			return self::invalid_grant( 'That code is not valid.' );
		}

		if ( $code->spent ) {
			if ( null !== $code->grant_id ) {
				$this->store->revoke_grant( $code->grant_id, 'code_reused', $now );
			}

			return self::invalid_grant( 'That code has already been used; the access it gave has been revoked.' );
		}

		if ( $code->expires_at < $now ) {
			return self::invalid_grant( 'That code has expired.' );
		}

		if ( ! hash_equals( $code->client_id, $client_id ) ) {
			return self::invalid_grant( 'That code was issued to another client.' );
		}

		if ( ! hash_equals( $code->redirect_uri, $form['redirect_uri'] ?? '' ) ) {
			return self::invalid_grant( 'redirect_uri does not match the authorization request.' );
		}

		$verifier = $form['code_verifier'] ?? '';

		if ( ! Pkce::valid( $verifier ) || ! hash_equals( $code->challenge, Pkce::challenge( $verifier ) ) ) {
			return self::invalid_grant( 'The code_verifier does not match the code_challenge.' );
		}

		if ( '' !== ( $form['resource'] ?? '' ) && ! Uri::same_resource( $code->resource, $form['resource'] ) ) {
			return new OAuthError( 'invalid_target', 'The resource does not match the authorization request.' )->reply();
		}

		$client = $this->store->find_client( $client_id );

		if ( null === $client ) {
			return self::invalid_grant( 'That client no longer exists.' );
		}

		$grant = $this->store->create_grant( $hash, $code, $client, $now );

		return $this->issue( $grant, $code->scopes, $client->refreshes(), $now );
	}

	/**
	 * Exchange a refresh token for new tokens.
	 *
	 * @param array<string, string> $form      The body.
	 * @param string                $client_id The caller.
	 *
	 * @return Reply
	 */
	private function refresh( array $form, string $client_id ): Reply {
		$presented = $form['refresh_token'] ?? '';
		$hash      = Token::digest( $presented );
		$token     = '' === $presented ? null : $this->store->find_token( $hash );
		$now       = $this->now();

		if ( null === $token || StoredToken::REFRESH !== $token->kind ) {
			return self::invalid_grant( 'That refresh token is not valid.' );
		}

		$grant = $this->store->find_grant( $token->grant_id );

		// Another client's token says nothing about that client's grant,
		// so it is refused without revoking anything.
		if ( null === $grant || ! hash_equals( $grant->client_id, $client_id ) ) {
			return self::invalid_grant( 'That refresh token is not valid.' );
		}

		if ( $token->spent ) {
			$this->store->revoke_grant( $grant->id, 'refresh_reused', $now );

			return self::invalid_grant( 'That refresh token was already used, so the access it belonged to has been revoked. Authorize again.' );
		}

		if ( ! $grant->active || $token->expires_at < $now ) {
			return self::invalid_grant( 'That refresh token has expired or been revoked.' );
		}

		if ( '' !== ( $form['resource'] ?? '' ) && ! Uri::same_resource( $grant->resource, $form['resource'] ) ) {
			return new OAuthError( 'invalid_target', 'The resource does not match the grant.' )->reply();
		}

		$scopes = $grant->scopes;

		if ( '' !== trim( $form['scope'] ?? '' ) ) {
			$asked = preg_split( '/ +/', trim( $form['scope'] ), -1, PREG_SPLIT_NO_EMPTY );

			if ( false === $asked || array() !== array_diff( $asked, $grant->scopes ) ) {
				return new OAuthError( 'invalid_scope', 'A refresh can narrow the scopes but not widen them.' )->reply();
			}

			// What the names imply today stays inside what was granted, so
			// a scope map changed since approval cannot widen a grant.
			$scopes = array_values( array_intersect( $this->settings->expand( $asked ), $grant->scopes ) );
		}

		// Two requests racing with the same token: one wins, and the
		// other is a reuse like any other.
		if ( ! $this->store->spend_refresh( $hash, $now ) ) {
			$this->store->revoke_grant( $grant->id, 'refresh_reused', $now );

			return self::invalid_grant( 'That refresh token was already used, so the access it belonged to has been revoked. Authorize again.' );
		}

		return $this->issue( $grant->id, $scopes, true, $now, $grant->scopes );
	}

	/**
	 * Mint an access token and, when the client refreshes, a refresh token.
	 *
	 * @param string        $grant   Grant id.
	 * @param string[]      $scopes  For the access token.
	 * @param bool          $refresh Whether to add a refresh token.
	 * @param int           $now     Unix time.
	 * @param string[]|null $granted For the refresh token; defaults to $scopes.
	 *
	 * @return Reply
	 */
	private function issue( string $grant, array $scopes, bool $refresh, int $now, ?array $granted = null ): Reply {
		$access = Token::api_key( $this->settings->access_prefix, 0 )['key'];

		$this->store->save_token( Token::digest( $access ), new StoredToken( $grant, StoredToken::ACCESS, $scopes, $now + $this->settings->access_ttl ), $now );

		$body = array(
			'access_token' => $access,
			'token_type'   => 'Bearer',
			'expires_in'   => $this->settings->access_ttl,
			'scope'        => implode( ' ', $scopes ),
		);

		if ( $refresh ) {
			$next = Token::api_key( $this->settings->refresh_prefix, 0 )['key'];

			$this->store->save_token( Token::digest( $next ), new StoredToken( $grant, StoredToken::REFRESH, $granted ?? $scopes, $now + $this->settings->refresh_ttl ), $now );

			$body['refresh_token'] = $next;
		}

		return new Reply( 200, $body );
	}

	/* ─── Revocation (RFC 7009) ─────────────────────────────────────── */

	/**
	 * Revoke a token.
	 *
	 * A refresh token takes its whole grant with it; an access token only
	 * itself (RFC 7009 §2.1). The answer is 200 whether or not the token
	 * existed or was this client's — the RFC's own choice, so the endpoint
	 * cannot be used to test tokens.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $form The form-encoded body.
	 *
	 * @return Reply
	 */
	public function revoke( array $form ): Reply {
		$presented = is_string( $form['token'] ?? null ) ? $form['token'] : '';
		$client_id = is_string( $form['client_id'] ?? null ) ? $form['client_id'] : '';

		if ( '' === $client_id ) {
			return new OAuthError( 'invalid_client', 'client_id is required.', 401 )->reply();
		}

		if ( '' === $presented ) {
			return new OAuthError( 'invalid_request', 'token is required.' )->reply();
		}

		$hash  = Token::digest( $presented );
		$token = $this->store->find_token( $hash );
		$grant = null === $token ? null : $this->store->find_grant( $token->grant_id );

		if ( null !== $token && null !== $grant && hash_equals( $grant->client_id, $client_id ) ) {
			if ( StoredToken::REFRESH === $token->kind ) {
				$this->store->revoke_grant( $grant->id, 'client', $this->now() );
			} else {
				$this->store->delete_token( $hash );
			}
		}

		return new Reply( 200, array() );
	}

	/* ─── Dynamic client registration (RFC 7591) ────────────────────── */

	/**
	 * Register a client.
	 *
	 * Kept for clients that predate metadata documents; MCP 2026-07-28 calls
	 * it deprecated. Rate-limit it: every call writes a row.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $body The decoded JSON body.
	 *
	 * @return Reply 201 with the registration, or 400.
	 */
	public function register( array $body ): Reply {
		if ( '' === $this->settings->registration_endpoint ) {
			return new OAuthError( 'invalid_request', 'This server does not register clients.' )->reply();
		}

		$client = ClientMetadata::registration( $body, Token::id( 'mcpc', 16 ) );

		if ( $client instanceof OAuthError ) {
			return $client->reply();
		}

		$now = $this->now();

		$this->store->save_client( $client, $now );

		return new Reply( 201, $client->registration( $now ) );
	}

	/* ─── The resource server's side ────────────────────────────────── */

	/**
	 * Who an access token acts for, or null.
	 *
	 * Null for anything not an access token of ours, expired, from a revoked
	 * grant, or bound to another resource (MCP: a server MUST only accept
	 * tokens issued for itself).
	 *
	 * @since 1.0.0
	 *
	 * @param string $presented The bearer token.
	 *
	 * @return array{grant: Grant, scopes: string[]}|null
	 */
	public function authenticate( #[\SensitiveParameter] string $presented ): ?array {
		if ( ! str_starts_with( $presented, $this->settings->access_prefix . '_' ) ) {
			return null;
		}

		$token = $this->store->find_token( Token::digest( $presented ) );
		$now   = $this->now();

		if ( null === $token || StoredToken::ACCESS !== $token->kind || $token->expires_at < $now ) {
			return null;
		}

		$grant = $this->store->find_grant( $token->grant_id );

		if ( null === $grant || ! $grant->active || ! Uri::same_resource( $grant->resource, $this->settings->resource ) ) {
			return null;
		}

		$this->store->touch_grant( $grant->id, $now );

		return array( 'grant' => $grant, 'scopes' => $token->scopes );
	}

	/* ─── Helpers ───────────────────────────────────────────────────── */

	/**
	 * The client a request names: stored, or fetched as a metadata document.
	 *
	 * @param string $id client_id.
	 *
	 * @return Client|OAuthError
	 */
	private function client( string $id ): Client|OAuthError {
		if ( '' === $id ) {
			return new OAuthError( 'invalid_request', 'client_id is required.' );
		}

		$now    = $this->now();
		$stored = $this->store->find_client( $id );

		if ( null !== $stored && ( ! $stored->document || ( $stored->expires_at ?? 0 ) > $now ) ) {
			return $stored;
		}

		if ( null === $this->documents || ! $this->settings->documents || ! ClientDocuments::is_document_id( $id ) ) {
			return new OAuthError( 'invalid_client', 'That client is not registered here.' );
		}

		$fetched = $this->documents->fetch( $id, $now );

		if ( $fetched instanceof Client ) {
			$this->store->save_client( $fetched, $now );
		}

		return $fetched;
	}

	/**
	 * The canonical resource a request is for, or null when it is not ours.
	 *
	 * @param string $asked The `resource` parameter.
	 *
	 * @return string|null
	 */
	private function resource( string $asked ): ?string {
		if ( '' === $asked || Uri::same_resource( $asked, $this->settings->resource ) ) {
			return Uri::resource( $this->settings->resource );
		}

		return null;
	}

	/**
	 * Now.
	 *
	 * @return int
	 */
	private function now(): int {
		return ( $this->clock )();
	}

	/**
	 * The usual refusal at the token endpoint.
	 *
	 * @param string $description Why.
	 *
	 * @return Reply
	 */
	private static function invalid_grant( string $description ): Reply {
		return new OAuthError( 'invalid_grant', $description )->reply();
	}
}
