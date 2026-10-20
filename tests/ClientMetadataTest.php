<?php
/**
 * Client metadata.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\OAuthServer\{Client, ClientMetadata, OAuthError};

/**
 * Class ClientMetadataTest
 */
final class ClientMetadataTest extends TestCase {

	/**
	 * Claude's hosted metadata document, as published on 21 October 2026.
	 */
	public const array CLAUDE = array(
		'client_id'                  => 'https://claude.ai/oauth/mcp-oauth-client-metadata',
		'client_name'                => 'Claude',
		'client_uri'                 => 'https://claude.ai',
		'redirect_uris'              => array( 'https://claude.ai/api/mcp/auth_callback' ),
		'grant_types'                => array( 'authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer' ),
		'response_types'             => array( 'code' ),
		'token_endpoint_auth_method' => 'none',
	);

	/**
	 * ChatGPT's, the same day: it names private_key_jwt and falls back to none.
	 */
	public const array CHATGPT = array(
		'client_id'                             => 'https://chatgpt.com/oauth/client.json',
		'client_name'                           => 'ChatGPT',
		'redirect_uris'                         => array( 'https://chatgpt.com/connector_platform_oauth_redirect' ),
		'grant_types'                           => array( 'authorization_code', 'refresh_token' ),
		'token_endpoint_auth_method'            => 'private_key_jwt',
		'token_endpoint_auth_methods_supported' => array( 'none', 'private_key_jwt' ),
		'jwks_uri'                              => 'https://chatgpt.com/oauth/jwks.json',
	);

	public function test_claudes_document_is_a_public_client_that_refreshes(): void {
		$client = ClientMetadata::document( self::CLAUDE, self::CLAUDE['client_id'], 100 );

		$this->assertInstanceOf( Client::class, $client );
		$this->assertSame( 'Claude', $client->name );
		$this->assertSame( array( 'authorization_code', 'refresh_token' ), $client->grant_types );
		$this->assertTrue( $client->document );
		$this->assertTrue( $client->refreshes() );
		$this->assertSame( 100, $client->expires_at );
		$this->assertSame( 'https://claude.ai', $client->uri );
	}

	public function test_chatgpts_document_is_accepted_as_a_public_client(): void {
		$client = ClientMetadata::document( self::CHATGPT, self::CHATGPT['client_id'], 100 );

		$this->assertInstanceOf( Client::class, $client );
		$this->assertTrue( $client->allows_redirect( 'https://chatgpt.com/connector_platform_oauth_redirect' ) );
	}

	public function test_a_document_must_name_the_url_it_was_fetched_from(): void {
		$error = ClientMetadata::document( self::CLAUDE, 'https://evil.example/claude.json', 100 );

		$this->assertInstanceOf( OAuthError::class, $error );
		$this->assertSame( 'invalid_client', $error->error );
	}

	public function test_a_document_cannot_use_a_shared_secret(): void {
		$this->assertInstanceOf( OAuthError::class, ClientMetadata::document( array( 'token_endpoint_auth_method' => 'client_secret_basic' ) + self::CLAUDE, self::CLAUDE['client_id'], 1 ) );
	}

	public function test_a_document_needs_a_name(): void {
		$this->assertInstanceOf( OAuthError::class, ClientMetadata::document( array( 'client_name' => " \n" ) + self::CLAUDE, self::CLAUDE['client_id'], 1 ) );
	}

	public function test_a_registration_with_no_redirect_uri_is_refused(): void {
		foreach ( array( array(), array( 'redirect_uris' => array() ), array( 'redirect_uris' => 'https://a.example/cb' ), array( 'redirect_uris' => array( 'x' => 'https://a.example/cb' ) ) ) as $body ) {
			$error = ClientMetadata::registration( $body, 'id' );

			$this->assertInstanceOf( OAuthError::class, $error );
			$this->assertSame( 'invalid_redirect_uri', $error->error );
		}
	}

	public function test_one_unsafe_redirect_uri_refuses_the_whole_registration(): void {
		foreach ( array( 'http://app.example.com/cb', 'https://a.example/cb#x', 'myapp://cb', 42 ) as $bad ) {
			$error = ClientMetadata::registration( array( 'redirect_uris' => array( 'https://ok.example/cb', $bad ) ), 'id' );

			$this->assertInstanceOf( OAuthError::class, $error, (string) json_encode( $bad ) );
		}
	}

	public function test_too_many_redirect_uris_are_refused(): void {
		$uris = array_map( static fn ( int $n ): string => 'https://a.example/cb' . $n, range( 1, ClientMetadata::MAX_REDIRECTS + 1 ) );

		$this->assertInstanceOf( OAuthError::class, ClientMetadata::registration( array( 'redirect_uris' => $uris ), 'id' ) );
	}

	public function test_a_registration_asking_for_a_secret_is_registered_public(): void {
		$client = ClientMetadata::registration( array(
			'redirect_uris'              => array( 'http://127.0.0.1:6274/oauth/callback' ),
			'token_endpoint_auth_method' => 'client_secret_basic',
			'client_name'                => 'MCP Inspector',
		), 'mcpc_1' );

		$this->assertInstanceOf( Client::class, $client );
		$this->assertSame( 'none', $client->registration( 5 )['token_endpoint_auth_method'] );
		$this->assertArrayNotHasKey( 'client_secret', $client->registration( 5 ) );
		$this->assertTrue( $client->local_only() );
	}

	public function test_without_grant_types_a_client_gets_codes_but_no_refresh(): void {
		$client = ClientMetadata::registration( array( 'redirect_uris' => array( 'https://a.example/cb' ) ), 'id' );

		$this->assertSame( array( 'authorization_code' ), $client->grant_types );
		$this->assertFalse( $client->refreshes() );
		$this->assertFalse( $client->local_only() );
	}

	public function test_a_client_that_cannot_use_codes_is_refused(): void {
		$error = ClientMetadata::registration( array( 'redirect_uris' => array( 'https://a.example/cb' ), 'grant_types' => array( 'client_credentials' ) ), 'id' );

		$this->assertInstanceOf( OAuthError::class, $error );
		$this->assertSame( 'invalid_client_metadata', $error->error );
		$this->assertInstanceOf( OAuthError::class, ClientMetadata::registration( array( 'redirect_uris' => array( 'https://a.example/cb' ), 'response_types' => array( 'token' ) ), 'id' ) );
	}

	public function test_a_name_is_one_short_line(): void {
		$client = ClientMetadata::registration( array( 'redirect_uris' => array( 'https://a.example/cb' ), 'client_name' => "Good\nApp\u{202E}" . str_repeat( 'x', 300 ) ), 'id' );

		$this->assertStringStartsWith( 'Good App', $client->name );
		$this->assertStringNotContainsString( "\u{202E}", $client->name );
		$this->assertSame( ClientMetadata::MAX_NAME, mb_strlen( $client->name ) );
	}

	public function test_a_client_uri_must_be_https(): void {
		$client = ClientMetadata::registration( array( 'redirect_uris' => array( 'https://a.example/cb' ), 'client_uri' => 'javascript:alert(1)' ), 'id' );

		$this->assertSame( '', $client->uri );
	}
}
