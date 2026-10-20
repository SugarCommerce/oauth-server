<?php
/**
 * Client ID Metadata Documents.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\HttpClient\{Fake, Response};
use SugarCommerce\OAuthServer\{Client, ClientDocuments, OAuthError};

/**
 * Class ClientDocumentsTest
 */
final class ClientDocumentsTest extends TestCase {

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function ids(): array {
		return array(
			'claude'         => array( 'https://claude.ai/oauth/mcp-oauth-client-metadata', true ),
			'chatgpt'        => array( 'https://chatgpt.com/oauth/client.json', true ),
			'no path'        => array( 'https://claude.ai', false ),
			'root path'      => array( 'https://claude.ai/', false ),
			'http'           => array( 'http://claude.ai/client.json', false ),
			'query'          => array( 'https://claude.ai/client.json?x=1', false ),
			'fragment'       => array( 'https://claude.ai/client.json#x', false ),
			'user info'      => array( 'https://a@claude.ai/client.json', false ),
			'dot segment'    => array( 'https://claude.ai/a/../client.json', false ),
			'odd port'       => array( 'https://claude.ai:8443/client.json', false ),
			'not a url'      => array( 'mcpc_0123456789abcdef', false ),
		);
	}

	#[DataProvider( 'ids' )]
	public function test_which_client_ids_are_documents( string $id, bool $document ): void {
		$this->assertSame( $document, ClientDocuments::is_document_id( $id ) );
	}

	public function test_a_document_is_fetched_validated_and_given_an_expiry(): void {
		$url  = ClientMetadataTest::CLAUDE['client_id'];
		$http = Fake::strict()->on( 'GET', $url, new Response( true, 200, (string) json_encode( ClientMetadataTest::CLAUDE ), headers: array( 'cache-control' => 'public, max-age=600' ) ) );

		$client = ( new ClientDocuments( $http ) )->fetch( $url, 1000 );

		$this->assertInstanceOf( Client::class, $client );
		$this->assertSame( 1600, $client->expires_at );
		$this->assertSame( 'application/json', $http->sent( 'GET', $url )[0]['headers']['Accept'] ?? null );
	}

	public function test_a_failed_or_malformed_fetch_is_an_invalid_client(): void {
		$url = 'https://example.com/client.json';

		foreach ( array( new Response( false, 404 ), new Response( true, 200, 'not json' ), new Response( true, 200, '[1,2]' ), Response::failure( 'blocked by SSRF policy' ) ) as $answer ) {
			$error = ( new ClientDocuments( Fake::strict()->on( 'GET', $url, $answer ) ) )->fetch( $url, 0 );

			$this->assertInstanceOf( OAuthError::class, $error );
			$this->assertSame( 'invalid_client', $error->error );
		}
	}

	public function test_nothing_is_fetched_for_an_id_that_is_not_a_document(): void {
		$http = Fake::strict();

		$this->assertInstanceOf( OAuthError::class, ( new ClientDocuments( $http ) )->fetch( 'http://169.254.169.254/latest', 0 ) );
		$this->assertSame( array(), $http->sent() );
	}

	public function test_the_cache_lifetime_is_clamped(): void {
		$this->assertSame( ClientDocuments::DEFAULT_CACHE, ClientDocuments::lifetime( null ) );
		$this->assertSame( ClientDocuments::MIN_CACHE, ClientDocuments::lifetime( 'max-age=0' ) );
		$this->assertSame( ClientDocuments::MIN_CACHE, ClientDocuments::lifetime( 'no-store' ) );
		$this->assertSame( ClientDocuments::MAX_CACHE, ClientDocuments::lifetime( 'max-age=99999999' ) );
		$this->assertSame( 7200, ClientDocuments::lifetime( 'Public, Max-Age=7200' ) );
	}
}
