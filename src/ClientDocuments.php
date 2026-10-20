<?php
/**
 * OAuth Client ID Metadata Documents.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

use SugarCommerce\HttpClient\Client as HttpClient;

/**
 * Class ClientDocuments
 *
 * draft-ietf-oauth-client-id-metadata-document-00, which the MCP
 * 2026-07-28 authorization spec prefers to dynamic registration: the
 * client_id is an HTTPS URL, and the document at that URL is the client's
 * registration. Nothing to store per connection, and the name on the
 * consent screen comes from a URL on the client's own domain rather than
 * from whoever posted to a registration endpoint.
 *
 * Fetching a URL a stranger chose is server-side request forgery waiting to
 * happen, so (CIMD §6, MCP "Authorization Server Abuse Protection"):
 *
 * - The HTTP client's SSRF policy is on: no private, loopback or link-local
 *   address, checked on the resolved IP.
 * - No redirects: the document must be at the URL that is its name.
 * - Five kilobytes at most, five seconds at most.
 * - The URL must be a plain https URL with a path — no user info, no
 *   fragment, no query, no dot segments — which also keeps one document
 *   from having many names.
 *
 * A fetched document is cached for as long as its Cache-Control says,
 * within five minutes and a day: long enough that a busy client is not
 * fetched on every authorization, short enough that a client whose
 * redirect URIs changed is not refused for long.
 *
 * @since 1.0.0
 */
final readonly class ClientDocuments {

	/**
	 * Largest document read.
	 */
	public const int MAX_BYTES = 5120;

	/**
	 * Shortest and longest a copy is kept, in seconds.
	 */
	public const int MIN_CACHE = 300;
	public const int MAX_CACHE = 86400;

	/**
	 * How long a copy is kept when the response does not say.
	 */
	public const int DEFAULT_CACHE = 3600;

	/**
	 * The HTTP client, configured for fetching documents.
	 */
	private HttpClient $http;

	/**
	 * @since 1.0.0
	 *
	 * @param HttpClient $http An SSRF-guarded client. Its timeout, size limit
	 *                         and redirect setting are overridden here.
	 */
	public function __construct( HttpClient $http = new HttpClient() ) {
		$this->http = $http->with_timeout( 5 )->with_max_bytes( self::MAX_BYTES )->following_redirects( 0 );
	}

	/**
	 * Whether a client_id is a metadata document URL.
	 *
	 * @since 1.0.0
	 *
	 * @param string $client_id Candidate.
	 *
	 * @return bool
	 */
	public static function is_document_id( string $client_id ): bool {
		if ( ! str_starts_with( $client_id, 'https://' ) || strlen( $client_id ) > 512 || 1 === preg_match( '/[\x00-\x20\x7f#?@\\\\]/', $client_id ) ) {
			return false;
		}

		$parts = parse_url( $client_id );

		if ( ! is_array( $parts ) || '' === ( $parts['host'] ?? '' ) || isset( $parts['port'] ) && 443 !== $parts['port'] ) {
			return false;
		}

		$path = $parts['path'] ?? '';

		return '' !== trim( $path, '/' ) && 1 !== preg_match( '#(^|/)\.{1,2}(/|$)#', $path );
	}

	/**
	 * Fetch and validate one.
	 *
	 * @since 1.0.0
	 *
	 * @param string $url The client_id.
	 * @param int    $now Unix time, for the expiry.
	 *
	 * @return Client|OAuthError
	 */
	public function fetch( string $url, int $now ): Client|OAuthError {
		if ( ! self::is_document_id( $url ) ) {
			return new OAuthError( 'invalid_client', 'That client_id is not a metadata document URL.' );
		}

		$response = $this->http->get( $url, array( 'Accept' => 'application/json' ) );

		if ( ! $response->ok || 200 !== $response->status ) {
			return new OAuthError( 'invalid_client', 'The client\'s metadata document could not be fetched.' );
		}

		$document = json_decode( $response->body, true );

		if ( ! is_array( $document ) || array_is_list( $document ) ) {
			return new OAuthError( 'invalid_client', 'The client\'s metadata document is not a JSON object.' );
		}

		return ClientMetadata::document( $document, $url, $now + self::lifetime( $response->header( 'cache-control' ) ) );
	}

	/**
	 * How long to keep a copy, from its Cache-Control.
	 *
	 * `no-store` and `no-cache` get the minimum, not zero: refetching on
	 * every authorization is a way to make us fetch a URL on demand.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $header Cache-Control.
	 *
	 * @return int Seconds.
	 */
	public static function lifetime( ?string $header ): int {
		$header = strtolower( (string) $header );

		if ( 1 === preg_match( '/\bmax-age\s*=\s*(\d+)/', $header, $match ) ) {
			return max( self::MIN_CACHE, min( self::MAX_CACHE, (int) $match[1] ) );
		}

		if ( str_contains( $header, 'no-store' ) || str_contains( $header, 'no-cache' ) ) {
			return self::MIN_CACHE;
		}

		return self::DEFAULT_CACHE;
	}
}
