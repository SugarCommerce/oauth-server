<?php
/**
 * Client metadata, validated.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class ClientMetadata
 *
 * One set of rules for both ways a client describes itself — an RFC 7591
 * registration request and a Client ID Metadata Document — because both
 * end up as the same thing: redirect URIs a code may be sent to, and a name
 * shown to a person deciding whether to trust it.
 *
 * Lenient where leniency is safe, strict where it is not:
 *
 * - **Redirect URIs** are refused outright when any one is unsafe (see
 *   {@see Uri::redirect_problem()}); there is no "the rest are fine".
 * - **Grant and response types** we do not support are dropped rather than
 *   refused (RFC 7591 §3.2.1 lets the server replace values). Claude's own
 *   metadata document lists the JWT bearer grant, and refusing it would
 *   refuse Claude. `authorization_code` must be among them.
 * - **The authentication method** is always `none` (see {@see Client}). A
 *   registration asking for a secret is registered without one, and the
 *   response says so; a metadata document claiming `client_secret_*` is
 *   refused, because the CIMD draft forbids it (a URL anybody can read
 *   cannot be the place a shared secret is agreed). `private_key_jwt` is
 *   accepted and treated as `none` — ChatGPT's document names it and falls
 *   back to `none` when that is all the server offers.
 * - **The name** is cut to 100 characters with control characters removed,
 *   because it is drawn on a consent screen.
 *
 * @since 1.0.0
 */
final readonly class ClientMetadata {

	/**
	 * Most redirect URIs one client may register.
	 */
	public const int MAX_REDIRECTS = 10;

	/**
	 * Longest name shown.
	 */
	public const int MAX_NAME = 100;

	/**
	 * Grant types a client may be given.
	 */
	private const array GRANTS = array( 'authorization_code', 'refresh_token' );

	/**
	 * A registration request (RFC 7591 §2), as a client.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $body The decoded JSON body.
	 * @param string               $id   The client_id to give it.
	 *
	 * @return Client|OAuthError
	 */
	public static function registration( array $body, string $id ): Client|OAuthError {
		return self::build( $body, $id, false, null );
	}

	/**
	 * A fetched metadata document, as a client.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed> $document   The decoded document.
	 * @param string               $url        Where it was fetched from.
	 * @param int                  $expires_at When the copy goes stale.
	 *
	 * @return Client|OAuthError
	 */
	public static function document( array $document, string $url, int $expires_at ): Client|OAuthError {
		// The document must name itself (CIMD §4.1): a document copied to
		// another URL is not that client's.
		if ( ! is_string( $document['client_id'] ?? null ) || ! hash_equals( $url, $document['client_id'] ) ) {
			return new OAuthError( 'invalid_client', 'The metadata document\'s client_id is not the URL it was fetched from.' );
		}

		$method = $document['token_endpoint_auth_method'] ?? 'none';

		if ( is_string( $method ) && str_starts_with( $method, 'client_secret' ) ) {
			return new OAuthError( 'invalid_client', 'A metadata document client cannot use a shared secret.' );
		}

		if ( '' === self::name( $document['client_name'] ?? null ) ) {
			return new OAuthError( 'invalid_client', 'The metadata document has no client_name.' );
		}

		return self::build( $document, $url, true, $expires_at );
	}

	/**
	 * The shared rules.
	 *
	 * @param array<string, mixed> $data       Metadata.
	 * @param string               $id         client_id.
	 * @param bool                 $document   From a metadata document.
	 * @param int|null             $expires_at For a document.
	 *
	 * @return Client|OAuthError
	 */
	private static function build( array $data, string $id, bool $document, ?int $expires_at ): Client|OAuthError {
		$code = $document ? 'invalid_client' : 'invalid_redirect_uri';
		$uris = $data['redirect_uris'] ?? null;

		if ( ! is_array( $uris ) || ! array_is_list( $uris ) || array() === $uris ) {
			return new OAuthError( $code, 'redirect_uris is required: a list of at least one URL.' );
		}

		if ( count( $uris ) > self::MAX_REDIRECTS ) {
			return new OAuthError( $code, 'At most ' . self::MAX_REDIRECTS . ' redirect URIs.' );
		}

		foreach ( $uris as $uri ) {
			$problem = is_string( $uri ) ? Uri::redirect_problem( $uri ) : 'Each redirect URI is a string.';

			if ( null !== $problem ) {
				return new OAuthError( $code, $problem );
			}
		}

		$grants = self::listed( $data['grant_types'] ?? null, array( 'authorization_code' ) );
		$grants = array_values( array_intersect( self::GRANTS, $grants ) );

		if ( ! in_array( 'authorization_code', $grants, true ) ) {
			return new OAuthError( $document ? 'invalid_client' : 'invalid_client_metadata', 'grant_types must include authorization_code.' );
		}

		if ( ! in_array( 'code', self::listed( $data['response_types'] ?? null, array( 'code' ) ), true ) ) {
			return new OAuthError( $document ? 'invalid_client' : 'invalid_client_metadata', 'response_types must include code.' );
		}

		$client_uri = is_string( $data['client_uri'] ?? null ) && str_starts_with( strtolower( $data['client_uri'] ), 'https://' ) && null === Uri::redirect_problem( $data['client_uri'] )
			? $data['client_uri']
			: '';

		return new Client(
			id: $id,
			name: self::name( $data['client_name'] ?? null ),
			redirect_uris: array_values( array_unique( $uris ) ),
			grant_types: $grants,
			document: $document,
			uri: $client_uri,
			expires_at: $expires_at,
		);
	}

	/**
	 * A list of strings, or the default when the field is absent.
	 *
	 * @param mixed    $value   The field.
	 * @param string[] $default When absent.
	 *
	 * @return string[]
	 */
	private static function listed( mixed $value, array $default ): array {
		if ( null === $value ) {
			return $default;
		}

		return is_array( $value ) ? array_values( array_filter( $value, 'is_string' ) ) : array();
	}

	/**
	 * A name fit to draw: one line, no control characters, capped.
	 *
	 * @param mixed $value The field.
	 *
	 * @return string
	 */
	private static function name( mixed $value ): string {
		if ( ! is_string( $value ) || ! mb_check_encoding( $value, 'UTF-8' ) ) {
			return '';
		}

		$value = trim( (string) preg_replace( '/[\p{Cc}\p{Cf}\s]+/u', ' ', $value ) );

		return mb_substr( $value, 0, self::MAX_NAME );
	}
}
