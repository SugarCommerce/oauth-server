<?php
/**
 * The authorization server, end to end.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Generate\Token;
use SugarCommerce\HttpClient\{Fake, Response};
use SugarCommerce\OAuth\Pkce;
use SugarCommerce\OAuthServer\{AuthorizationRequest, AuthorizationServer, Client, ClientDocuments, Grant, OAuthError, Reply, Settings, StoredToken};

/**
 * Class AuthorizationServerTest
 *
 * The flow a client runs — authorize, approve, exchange, use, refresh,
 * revoke — and each way of getting it wrong.
 */
final class AuthorizationServerTest extends TestCase {

	private const string RESOURCE = 'https://api.example.com/mcp';
	private const string REDIRECT = 'https://client.example/callback';

	private MemoryStore $store;
	private int $now = 1_000_000;
	private AuthorizationServer $server;

	/** @var array{verifier: string, challenge: string} */
	private array $pkce;

	protected function setUp(): void {
		$this->store = new MemoryStore();
		$this->store->save_client( new Client( 'mcpc_test', 'Test Client', array( self::REDIRECT, 'http://127.0.0.1/callback' ), array( 'authorization_code', 'refresh_token' ) ), 0 );
		$this->server = $this->server();
		$this->pkce   = Pkce::pair();
	}

	/**
	 * The server under test, with a clock this test controls.
	 */
	private function server( ?ClientDocuments $documents = null, string $registration = 'https://api.example.com/oauth/register' ): AuthorizationServer {
		return new AuthorizationServer( self::settings( $registration ), $this->store, $documents, fn (): int => $this->now );
	}

	/**
	 * Settings with a read and a write scope.
	 */
	private static function settings( string $registration = 'https://api.example.com/oauth/register' ): Settings {
		return new Settings(
			issuer: 'https://api.example.com',
			resource: self::RESOURCE,
			authorization_endpoint: 'https://app.example.com/oauth/authorize',
			token_endpoint: 'https://api.example.com/oauth/token',
			revocation_endpoint: 'https://api.example.com/oauth/revoke',
			registration_endpoint: $registration,
			scopes: array( 'shop:read' => array(), 'shop:write' => array( 'shop:read' ) ),
			resource_name: 'Example',
		);
	}

	/**
	 * A well-formed authorization request.
	 *
	 * @param array<string, string> $changes Overrides; null-like '' removes.
	 *
	 * @return array<string, string>
	 */
	private function query( array $changes = array() ): array {
		return array_filter( $changes + array(
			'response_type'         => 'code',
			'client_id'             => 'mcpc_test',
			'redirect_uri'          => self::REDIRECT,
			'code_challenge'        => $this->pkce['challenge'],
			'code_challenge_method' => 'S256',
			'resource'              => self::RESOURCE,
			'scope'                 => 'shop:read shop:write',
			'state'                 => 'xyz-state',
		), static fn ( string $v ): bool => '' !== $v );
	}

	/**
	 * Authorize and approve: the code from the redirect.
	 */
	private function code( array $scopes = array( 'shop:write' ), array $query = array() ): string {
		$request = $this->server->authorize( $this->query( $query ) );

		$this->assertInstanceOf( AuthorizationRequest::class, $request );

		parse_str( (string) parse_url( $this->server->approve( $request, 'acct_1', $scopes, array( 'mode' => 'live' ) ), PHP_URL_QUERY ), $back );

		return (string) $back['code'];
	}

	/**
	 * Exchange a code.
	 */
	private function exchange( string $code, array $changes = array() ): Reply {
		return $this->server->token( $changes + array(
			'grant_type'    => 'authorization_code',
			'code'          => $code,
			'client_id'     => 'mcpc_test',
			'redirect_uri'  => self::REDIRECT,
			'code_verifier' => $this->pkce['verifier'],
			'resource'      => self::RESOURCE,
		) );
	}

	/**
	 * Use a refresh token.
	 */
	private function refresh( string $token, array $changes = array() ): Reply {
		return $this->server->token( $changes + array( 'grant_type' => 'refresh_token', 'refresh_token' => $token, 'client_id' => 'mcpc_test', 'resource' => self::RESOURCE ) );
	}

	/* ─── Metadata ─────────────────────────────────────────────────── */

	public function test_the_metadata_documents_say_what_the_server_does(): void {
		$server   = self::settings()->server_metadata();
		$resource = self::settings()->resource_metadata();

		$this->assertSame( 'https://api.example.com', $server['issuer'] );
		$this->assertSame( array( 'S256' ), $server['code_challenge_methods_supported'] );
		$this->assertSame( array( 'none' ), $server['token_endpoint_auth_methods_supported'] );
		$this->assertTrue( $server['authorization_response_iss_parameter_supported'] );
		$this->assertTrue( $server['client_id_metadata_document_supported'] );
		$this->assertSame( 'https://api.example.com/oauth/register', $server['registration_endpoint'] );
		$this->assertSame( array( 'code' ), $server['response_types_supported'] );
		$this->assertSame( array( 'authorization_code', 'refresh_token' ), $server['grant_types_supported'] );
		$this->assertNotContains( 'offline_access', $server['scopes_supported'] );

		$this->assertSame( self::RESOURCE, $resource['resource'] );
		$this->assertSame( array( 'https://api.example.com' ), $resource['authorization_servers'] );
		$this->assertSame( array( 'shop:read', 'shop:write' ), $resource['scopes_supported'] );
		$this->assertSame( array( 'header' ), $resource['bearer_methods_supported'] );

		$this->assertSame( 'https://api.example.com/.well-known/oauth-protected-resource/mcp', self::settings()->resource_metadata_url() );
		$this->assertSame( 'https://api.example.com/.well-known/oauth-authorization-server', self::settings()->server_metadata_url() );
	}

	public function test_without_a_registration_endpoint_none_is_advertised_or_served(): void {
		$this->assertArrayNotHasKey( 'registration_endpoint', self::settings( '' )->server_metadata() );
		$this->assertSame( 400, $this->server( null, '' )->register( array( 'redirect_uris' => array( self::REDIRECT ) ) )->status );
	}

	public function test_settings_refuse_a_bad_issuer(): void {
		$this->expectException( \InvalidArgumentException::class );

		new Settings( 'https://a.example/?x', self::RESOURCE, 'https://a/', 'https://a/', 'https://a/' );
	}

	public function test_write_implies_read_and_unknown_scopes_are_dropped(): void {
		$this->assertSame( array( 'shop:read', 'shop:write' ), self::settings()->expand( 'shop:write' ) );
		$this->assertSame( array( 'shop:read' ), self::settings()->expand( 'openid shop:read offline_access' ) );
		$this->assertSame( array(), self::settings()->expand( '' ) );
	}

	/* ─── The happy path ───────────────────────────────────────────── */

	public function test_code_and_pkce_give_resource_bound_tokens(): void {
		$request = $this->server->authorize( $this->query() );

		$this->assertInstanceOf( AuthorizationRequest::class, $request );
		$this->assertSame( 'client.example', $request->redirect_host() );
		$this->assertSame( array( 'shop:read', 'shop:write' ), $request->scopes );

		$redirect = $this->server->approve( $request, 'acct_1', array( 'shop:write' ), array( 'mode' => 'live' ) );

		$this->assertStringStartsWith( self::REDIRECT . '?code=', $redirect );
		parse_str( (string) parse_url( $redirect, PHP_URL_QUERY ), $back );
		$this->assertSame( 'xyz-state', $back['state'] );
		$this->assertSame( 'https://api.example.com', $back['iss'] );

		$reply = $this->exchange( (string) $back['code'] );

		$this->assertSame( 200, $reply->status, $reply->json() );
		$this->assertSame( 'Bearer', $reply->body['token_type'] );
		$this->assertSame( 3600, $reply->body['expires_in'] );
		$this->assertSame( 'shop:read shop:write', $reply->body['scope'] );
		$this->assertStringStartsWith( 'oat_', $reply->body['access_token'] );
		$this->assertStringStartsWith( 'ort_', $reply->body['refresh_token'] );
		$this->assertSame( 'no-store', $reply->headers()['Cache-Control'] );

		$who = $this->server->authenticate( $reply->body['access_token'] );

		$this->assertNotNull( $who );
		$this->assertSame( 'acct_1', $who['grant']->subject );
		$this->assertSame( array( 'mode' => 'live' ), $who['grant']->context );
		$this->assertSame( 'Test Client', $who['grant']->client_name );
		$this->assertSame( array( 'shop:read', 'shop:write' ), $who['scopes'] );
	}

	public function test_tokens_are_stored_only_as_digests(): void {
		$reply = $this->exchange( $this->code() );

		$this->assertArrayNotHasKey( $reply->body['access_token'], $this->store->tokens );
		$this->assertArrayHasKey( Token::digest( $reply->body['access_token'] ), $this->store->tokens );
		$this->assertArrayHasKey( Token::digest( $reply->body['refresh_token'] ), $this->store->tokens );
	}

	public function test_the_person_may_approve_less_than_was_asked(): void {
		$reply = $this->exchange( $this->code( array( 'shop:read' ) ) );

		$this->assertSame( 'shop:read', $reply->body['scope'] );
		$this->assertSame( array( 'shop:read' ), $this->server->authenticate( $reply->body['access_token'] )['scopes'] );
	}

	public function test_a_request_without_scope_or_resource_asks_for_everything_here(): void {
		$request = $this->server->authorize( $this->query( array( 'scope' => '', 'resource' => '' ) ) );

		$this->assertInstanceOf( AuthorizationRequest::class, $request );
		$this->assertSame( array( 'shop:read', 'shop:write' ), $request->scopes );
		$this->assertSame( self::RESOURCE, $request->resource );
	}

	public function test_no_state_means_none_comes_back(): void {
		$request = $this->server->authorize( $this->query( array( 'state' => '' ) ) );

		$this->assertStringNotContainsString( 'state=', $this->server->approve( $request, 'acct_1', array( 'shop:read' ) ) );
	}

	public function test_a_client_without_refresh_gets_no_refresh_token(): void {
		$this->store->save_client( new Client( 'mcpc_test', 'Test Client', array( self::REDIRECT ) ), 0 );

		$this->assertArrayNotHasKey( 'refresh_token', $this->exchange( $this->code() )->body );
	}

	public function test_a_loopback_client_may_come_back_on_any_port(): void {
		$query   = array( 'redirect_uri' => 'http://127.0.0.1:61234/callback' );
		$reply   = $this->exchange( $this->code( array( 'shop:read' ), $query ), $query );

		$this->assertSame( 200, $reply->status, $reply->json() );
	}

	/* ─── Authorization errors ─────────────────────────────────────── */

	/**
	 * Until the client and redirect URI are known, nothing is redirected.
	 */
	public function test_an_unknown_client_or_redirect_is_shown_not_redirected(): void {
		foreach ( array(
			array( 'client_id' => 'mcpc_nobody' ),
			array( 'client_id' => '' ),
			array( 'redirect_uri' => 'https://evil.example/callback' ),
			array( 'redirect_uri' => self::REDIRECT . '/' ),
			array( 'redirect_uri' => '' ),
		) as $changes ) {
			$error = $this->server->authorize( $this->query( $changes ) );

			$this->assertInstanceOf( OAuthError::class, $error, (string) json_encode( $changes ) );
			$this->assertFalse( $error->redirect );
			$this->assertNull( $this->server->error_url( $this->query( $changes ), $error ) );
		}
	}

	public function test_plain_pkce_is_refused(): void {
		$plain = $this->server->authorize( $this->query( array( 'code_challenge_method' => 'plain' ) ) );
		$none  = $this->server->authorize( $this->query( array( 'code_challenge_method' => '' ) ) );

		$this->assertInstanceOf( OAuthError::class, $plain );
		$this->assertSame( 'invalid_request', $plain->error );
		$this->assertTrue( $plain->redirect );
		$this->assertInstanceOf( OAuthError::class, $none );
	}

	public function test_a_missing_or_malformed_challenge_is_refused(): void {
		$this->assertInstanceOf( OAuthError::class, $this->server->authorize( $this->query( array( 'code_challenge' => '' ) ) ) );
		$this->assertInstanceOf( OAuthError::class, $this->server->authorize( $this->query( array( 'code_challenge' => 'short' ) ) ) );
	}

	public function test_redirected_errors_carry_state_and_iss(): void {
		$query = $this->query( array( 'response_type' => 'token' ) );
		$error = $this->server->authorize( $query );

		$this->assertInstanceOf( OAuthError::class, $error );
		$this->assertSame( 'unsupported_response_type', $error->error );

		parse_str( (string) parse_url( (string) $this->server->error_url( $query, $error ), PHP_URL_QUERY ), $back );

		$this->assertSame( 'unsupported_response_type', $back['error'] );
		$this->assertSame( 'xyz-state', $back['state'] );
		$this->assertSame( 'https://api.example.com', $back['iss'] );
	}

	/**
	 * A redirectable error is only as good as the query it is paired with:
	 * another request's redirect_uri must not be trusted on its say-so.
	 */
	public function test_a_redirectable_error_is_not_sent_to_an_unchecked_redirect(): void {
		$error = $this->server->authorize( $this->query( array( 'response_type' => 'token' ) ) );

		$this->assertInstanceOf( OAuthError::class, $error );
		$this->assertTrue( $error->redirect );

		foreach ( array(
			array( 'redirect_uri' => 'https://evil.example/callback' ),
			array( 'client_id' => 'mcpc_nobody' ),
			array( 'redirect_uri' => '' ),
		) as $changes ) {
			$this->assertNull( $this->server->error_url( $this->query( $changes ), $error ), (string) json_encode( $changes ) );
		}

		$this->assertNull( $this->server->error_url( array( 'client_id' => 'mcpc_test', 'redirect_uri' => array( self::REDIRECT ) ), $error ) );
	}

	public function test_another_resource_is_an_invalid_target(): void {
		$error = $this->server->authorize( $this->query( array( 'resource' => 'https://other.example/mcp' ) ) );

		$this->assertInstanceOf( OAuthError::class, $error );
		$this->assertSame( 'invalid_target', $error->error );
	}

	public function test_the_resource_may_differ_only_in_canonical_form(): void {
		$this->assertInstanceOf( AuthorizationRequest::class, $this->server->authorize( $this->query( array( 'resource' => 'HTTPS://API.EXAMPLE.COM/mcp/' ) ) ) );
	}

	public function test_deny_sends_access_denied_back_with_state(): void {
		$request = $this->server->authorize( $this->query() );

		parse_str( (string) parse_url( $this->server->deny( $request ), PHP_URL_QUERY ), $back );

		$this->assertSame( 'access_denied', $back['error'] );
		$this->assertSame( 'xyz-state', $back['state'] );
		$this->assertSame( 'https://api.example.com', $back['iss'] );
		$this->assertArrayNotHasKey( 'code', $back );
	}

	/* ─── Token endpoint errors ────────────────────────────────────── */

	public function test_a_wrong_verifier_gets_nothing_and_burns_the_code(): void {
		$code  = $this->code();
		$wrong = $this->exchange( $code, array( 'code_verifier' => Pkce::pair()['verifier'] ) );

		$this->assertSame( 400, $wrong->status );
		$this->assertSame( 'invalid_grant', $wrong->body['error'] );
		$this->assertSame( 400, $this->exchange( $code )->status );
	}

	public function test_a_missing_verifier_is_refused(): void {
		$this->assertSame( 'invalid_grant', $this->exchange( $this->code(), array( 'code_verifier' => '' ) )->body['error'] );
	}

	public function test_the_redirect_uri_must_match_the_authorization_request(): void {
		$this->assertSame( 'invalid_grant', $this->exchange( $this->code(), array( 'redirect_uri' => 'http://127.0.0.1/callback' ) )->body['error'] );
		$this->assertSame( 'invalid_grant', $this->exchange( $this->code(), array( 'redirect_uri' => '' ) )->body['error'] );
	}

	public function test_another_clients_code_is_refused(): void {
		$this->store->save_client( new Client( 'mcpc_other', 'Other', array( self::REDIRECT ) ), 0 );

		$this->assertSame( 'invalid_grant', $this->exchange( $this->code(), array( 'client_id' => 'mcpc_other' ) )->body['error'] );
	}

	public function test_a_missing_client_id_is_an_invalid_client(): void {
		$reply = $this->exchange( $this->code(), array( 'client_id' => '' ) );

		$this->assertSame( 401, $reply->status );
		$this->assertSame( 'invalid_client', $reply->body['error'] );
	}

	public function test_an_expired_code_is_refused(): void {
		$code       = $this->code();
		$this->now += 61;

		$this->assertSame( 'invalid_grant', $this->exchange( $code )->body['error'] );
	}

	public function test_a_token_for_another_resource_is_not_issued(): void {
		$reply = $this->exchange( $this->code(), array( 'resource' => 'https://other.example/mcp' ) );

		$this->assertSame( 'invalid_target', $reply->body['error'] );
	}

	/**
	 * OAuth 2.1 §4.1.3: a code used twice revokes what it gave.
	 */
	public function test_a_code_used_twice_revokes_the_grant(): void {
		$code   = $this->code();
		$first  = $this->exchange( $code );
		$second = $this->exchange( $code );

		$this->assertSame( 200, $first->status );
		$this->assertSame( 'invalid_grant', $second->body['error'] );
		$this->assertNull( $this->server->authenticate( $first->body['access_token'] ) );
		$this->assertSame( 'code_reused', $this->store->revoked['g1'] );
	}

	public function test_unknown_grant_types_are_refused(): void {
		$this->assertSame( 'unsupported_grant_type', $this->server->token( array( 'grant_type' => 'client_credentials', 'client_id' => 'mcpc_test' ) )->body['error'] );
		$this->assertSame( 'unsupported_grant_type', $this->server->token( array( 'grant_type' => 'password', 'client_id' => 'mcpc_test' ) )->body['error'] );
	}

	public function test_a_made_up_code_is_refused(): void {
		$this->assertSame( 'invalid_grant', $this->exchange( 'made-up' )->body['error'] );
		$this->assertSame( 'invalid_grant', $this->exchange( '' )->body['error'] );
	}

	/* ─── Access tokens ────────────────────────────────────────────── */

	public function test_an_expired_access_token_is_refused(): void {
		$access     = $this->exchange( $this->code() )->body['access_token'];
		$this->now += 3601;

		$this->assertNull( $this->server->authenticate( $access ) );
	}

	/**
	 * MCP: a server MUST only accept tokens issued for itself.
	 */
	public function test_a_token_bound_to_another_resource_is_refused(): void {
		$access = 'oat_' . Token::url_safe( 32 );

		$this->store->grants['other'] = new Grant( 'other', 'mcpc_test', array( 'shop:read' ), 'https://other.example/mcp', 'acct_1' );
		$this->store->save_token( Token::digest( $access ), new StoredToken( 'other', StoredToken::ACCESS, array( 'shop:read' ), $this->now + 60 ), $this->now );

		$this->assertNull( $this->server->authenticate( $access ) );
	}

	public function test_a_refresh_token_is_not_an_access_token(): void {
		$tokens = $this->exchange( $this->code() )->body;

		$this->assertNull( $this->server->authenticate( $tokens['refresh_token'] ) );
		$this->assertNull( $this->server->authenticate( 'scmcp_live_' . Token::url_safe( 32 ) ) );
		$this->assertNull( $this->server->authenticate( '' ) );
	}

	/* ─── Refresh ──────────────────────────────────────────────────── */

	public function test_a_refresh_rotates_both_tokens(): void {
		$first  = $this->exchange( $this->code() )->body;
		$second = $this->refresh( $first['refresh_token'] );

		$this->assertSame( 200, $second->status, $second->json() );
		$this->assertNotSame( $first['refresh_token'], $second->body['refresh_token'] );
		$this->assertNotSame( $first['access_token'], $second->body['access_token'] );
		$this->assertNotNull( $this->server->authenticate( $second->body['access_token'] ) );
		$this->assertSame( 200, $this->refresh( $second->body['refresh_token'] )->status );
	}

	/**
	 * OAuth 2.1 §4.3.1: a spent refresh token presented again is a theft,
	 * and the whole grant goes.
	 */
	public function test_a_reused_refresh_token_revokes_the_grant(): void {
		$first  = $this->exchange( $this->code() )->body;
		$second = $this->refresh( $first['refresh_token'] )->body;
		$reuse  = $this->refresh( $first['refresh_token'] );

		$this->assertSame( 'invalid_grant', $reuse->body['error'] );
		$this->assertSame( 'refresh_reused', $this->store->revoked['g1'] );
		$this->assertNull( $this->server->authenticate( $second['access_token'] ) );
		$this->assertSame( 'invalid_grant', $this->refresh( $second['refresh_token'] )->body['error'] );
	}

	public function test_another_client_cannot_use_or_burn_a_refresh_token(): void {
		$this->store->save_client( new Client( 'mcpc_other', 'Other', array( self::REDIRECT ), array( 'authorization_code', 'refresh_token' ) ), 0 );
		$first = $this->exchange( $this->code() )->body;

		$this->assertSame( 'invalid_grant', $this->refresh( $first['refresh_token'], array( 'client_id' => 'mcpc_other' ) )->body['error'] );
		$this->assertSame( 200, $this->refresh( $first['refresh_token'] )->status );
	}

	public function test_an_expired_refresh_token_is_refused(): void {
		$first      = $this->exchange( $this->code() )->body;
		$this->now += 2_592_001;

		$this->assertSame( 'invalid_grant', $this->refresh( $first['refresh_token'] )->body['error'] );
	}

	public function test_a_refresh_may_narrow_scopes_but_never_widen_them(): void {
		$full   = $this->exchange( $this->code() )->body;
		$narrow = $this->refresh( $full['refresh_token'], array( 'scope' => 'shop:read' ) )->body;

		$this->assertSame( 'shop:read', $narrow['scope'] );
		// The grant keeps what was approved: the next refresh can widen back.
		$this->assertSame( 'shop:read shop:write', $this->refresh( $narrow['refresh_token'] )->body['scope'] );

		$readonly = $this->exchange( $this->code( array( 'shop:read' ) ) )->body;

		$this->assertSame( 'invalid_scope', $this->refresh( $readonly['refresh_token'], array( 'scope' => 'shop:write' ) )->body['error'] );
	}

	/**
	 * A scope map changed after approval — `shop:read` now implying more —
	 * cannot widen what a refresh hands out beyond the grant.
	 */
	public function test_a_narrowing_refresh_stays_inside_the_grant_when_scopes_change(): void {
		$full = $this->exchange( $this->code( array( 'shop:read' ) ) )->body;

		$changed = new Settings(
			issuer: 'https://api.example.com',
			resource: self::RESOURCE,
			authorization_endpoint: 'https://app.example.com/oauth/authorize',
			token_endpoint: 'https://api.example.com/oauth/token',
			revocation_endpoint: 'https://api.example.com/oauth/revoke',
			scopes: array( 'shop:read' => array( 'shop:admin' ), 'shop:write' => array( 'shop:read' ), 'shop:admin' => array() ),
		);
		$server  = new AuthorizationServer( $changed, $this->store, null, fn (): int => $this->now );
		$reply   = $server->token( array( 'grant_type' => 'refresh_token', 'refresh_token' => $full['refresh_token'], 'client_id' => 'mcpc_test', 'scope' => 'shop:read' ) );

		$this->assertSame( 200, $reply->status, $reply->json() );
		$this->assertSame( 'shop:read', $reply->body['scope'] );
		$this->assertSame( array( 'shop:read' ), $server->authenticate( $reply->body['access_token'] )['scopes'] ?? null );
	}

	public function test_a_refresh_for_another_resource_is_refused(): void {
		$first = $this->exchange( $this->code() )->body;

		$this->assertSame( 'invalid_target', $this->refresh( $first['refresh_token'], array( 'resource' => 'https://other.example/mcp' ) )->body['error'] );
	}

	/* ─── Revocation ───────────────────────────────────────────────── */

	public function test_revoking_a_refresh_token_ends_the_grant(): void {
		$tokens = $this->exchange( $this->code() )->body;
		$reply  = $this->server->revoke( array( 'token' => $tokens['refresh_token'], 'client_id' => 'mcpc_test' ) );

		$this->assertSame( 200, $reply->status );
		$this->assertSame( '{}', $reply->json() );
		$this->assertNull( $this->server->authenticate( $tokens['access_token'] ) );
		$this->assertSame( 'client', $this->store->revoked['g1'] );
	}

	public function test_revoking_an_access_token_ends_only_that_token(): void {
		$tokens = $this->exchange( $this->code() )->body;

		$this->server->revoke( array( 'token' => $tokens['access_token'], 'client_id' => 'mcpc_test', 'token_type_hint' => 'access_token' ) );

		$this->assertNull( $this->server->authenticate( $tokens['access_token'] ) );
		$this->assertSame( 200, $this->refresh( $tokens['refresh_token'] )->status );
	}

	public function test_revocation_answers_the_same_whatever_the_token(): void {
		$tokens = $this->exchange( $this->code() )->body;

		$this->assertSame( 200, $this->server->revoke( array( 'token' => 'nothing', 'client_id' => 'mcpc_test' ) )->status );
		$this->assertSame( 200, $this->server->revoke( array( 'token' => $tokens['refresh_token'], 'client_id' => 'mcpc_other' ) )->status );
		$this->assertNotNull( $this->server->authenticate( $tokens['access_token'] ), 'Another client cannot revoke it.' );
		$this->assertSame( 401, $this->server->revoke( array( 'token' => 'x' ) )->status );
		$this->assertSame( 400, $this->server->revoke( array( 'client_id' => 'mcpc_test' ) )->status );
	}

	/* ─── Registration ─────────────────────────────────────────────── */

	public function test_a_client_registers_and_can_then_authorize(): void {
		$reply = $this->server->register( array(
			'client_name'   => 'My Assistant',
			'redirect_uris' => array( 'https://assistant.example/cb' ),
			'grant_types'   => array( 'authorization_code', 'refresh_token' ),
		) );

		$this->assertSame( 201, $reply->status, $reply->json() );
		$this->assertStringStartsWith( 'mcpc_', $reply->body['client_id'] );
		$this->assertSame( 'none', $reply->body['token_endpoint_auth_method'] );
		$this->assertSame( $this->now, $reply->body['client_id_issued_at'] );
		$this->assertArrayNotHasKey( 'client_secret', $reply->body );

		$request = $this->server->authorize( $this->query( array( 'client_id' => $reply->body['client_id'], 'redirect_uri' => 'https://assistant.example/cb' ) ) );

		$this->assertInstanceOf( AuthorizationRequest::class, $request );
		$this->assertSame( 'My Assistant', $request->client->name );
	}

	public function test_a_bad_registration_is_refused_and_stores_nothing(): void {
		$reply = $this->server->register( array( 'redirect_uris' => array( 'http://evil.example/cb' ) ) );

		$this->assertSame( 400, $reply->status );
		$this->assertSame( 'invalid_redirect_uri', $reply->body['error'] );
		$this->assertCount( 1, $this->store->clients );
	}

	/* ─── Metadata documents ───────────────────────────────────────── */

	public function test_a_metadata_document_client_is_fetched_once_and_cached(): void {
		$url  = ClientMetadataTest::CLAUDE['client_id'];
		$http = Fake::strict()->on( 'GET', $url, new Response( true, 200, (string) json_encode( ClientMetadataTest::CLAUDE ), headers: array( 'cache-control' => 'max-age=600' ) ) );

		$this->server = $this->server( new ClientDocuments( $http ) );

		$query = $this->query( array( 'client_id' => $url, 'redirect_uri' => 'https://claude.ai/api/mcp/auth_callback' ) );

		$this->assertInstanceOf( AuthorizationRequest::class, $this->server->authorize( $query ) );
		$this->assertInstanceOf( AuthorizationRequest::class, $this->server->authorize( $query ) );
		$this->assertCount( 1, $http->sent() );

		$this->now += 601;

		$this->assertInstanceOf( AuthorizationRequest::class, $this->server->authorize( $query ) );
		$this->assertCount( 2, $http->sent(), 'A stale copy is fetched again.' );

		$this->assertFalse( $this->server->authorize( array( 'redirect_uri' => 'https://evil.example/cb' ) + $query )->redirect );
	}

	public function test_documents_are_not_fetched_when_turned_off(): void {
		$http         = Fake::strict();
		$this->server = $this->server();

		$error = $this->server->authorize( $this->query( array( 'client_id' => 'https://claude.ai/oauth/mcp-oauth-client-metadata' ) ) );

		$this->assertInstanceOf( OAuthError::class, $error );
		$this->assertSame( array(), $http->sent() );
	}
}
