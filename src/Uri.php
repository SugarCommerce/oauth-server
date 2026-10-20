<?php
/**
 * The URI rules an authorization server lives or dies by.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class Uri
 *
 * Three questions, each a classic way in when answered loosely:
 *
 * - **Is this a redirect URI we may ever send a code to?** HTTPS, or plain
 *   HTTP to this machine's loopback for a native client (MCP 2026-07-28,
 *   "Communication Security": "All redirect URIs MUST be either localhost
 *   or use HTTPS"). No fragment, no user info — `https://good.example@evil
 *   .example/` is a redirect to evil.example.
 * - **Does a presented redirect URI match a registered one?** Exactly, as
 *   strings (OAuth 2.1 §2.3.1 and RFC 9700 §4.1.3). The one exception is the
 *   port of a loopback redirect, which OAuth 2.1 §8.4.2 says the server MUST
 *   allow to vary: a native app gets whatever port the OS hands it.
 * - **Is this token's audience us?** RFC 8707 resource indicators, compared
 *   in the canonical form the MCP authorization spec defines: lowercase
 *   scheme and host, no fragment, no default port, no trailing slash.
 *
 * @since 1.0.0
 */
final readonly class Uri {

	/**
	 * Hosts that are this machine.
	 */
	private const array LOOPBACK = array( '127.0.0.1', '[::1]', 'localhost' );

	/**
	 * The canonical form of a resource indicator, or null when it is not one.
	 *
	 * An absolute http(s) URI without a fragment (RFC 8707 §2). Scheme and
	 * host are lowercased and a default port dropped, so the uppercase forms
	 * the MCP spec says to accept compare equal; a lone trailing slash is
	 * dropped, the form the spec recommends.
	 *
	 * @since 1.0.0
	 *
	 * @param string $uri Candidate.
	 *
	 * @return string|null
	 */
	public static function resource( string $uri ): ?string {
		$parts = self::parts( $uri );

		if ( null === $parts || isset( $parts['fragment'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return null;
		}

		$path = $parts['path'] ?? '';

		if ( '/' === $path ) {
			$path = '';
		} elseif ( str_ends_with( $path, '/' ) ) {
			$path = rtrim( $path, '/' );
		}

		return $parts['scheme'] . '://' . $parts['host'] . self::port( $parts ) . $path . ( isset( $parts['query'] ) ? '?' . $parts['query'] : '' );
	}

	/**
	 * Whether two resource indicators name the same resource.
	 *
	 * @since 1.0.0
	 *
	 * @param string $a One.
	 * @param string $b The other.
	 *
	 * @return bool False when either is not a resource indicator at all.
	 */
	public static function same_resource( string $a, string $b ): bool {
		$a = self::resource( $a );
		$b = self::resource( $b );

		return null !== $a && null !== $b && hash_equals( $a, $b );
	}

	/**
	 * Why a URI cannot be a redirect URI, or null when it can.
	 *
	 * @since 1.0.0
	 *
	 * @param string $uri Candidate.
	 *
	 * @return string|null A sentence for the error_description.
	 */
	public static function redirect_problem( string $uri ): ?string {
		if ( strlen( $uri ) > 2000 ) {
			return 'A redirect URI is at most 2,000 characters.';
		}

		$parts = self::parts( $uri );

		if ( null === $parts ) {
			return 'A redirect URI must be an absolute http or https URL.';
		}

		if ( isset( $parts['fragment'] ) || str_contains( $uri, '#' ) ) {
			return 'A redirect URI must not have a fragment.';
		}

		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return 'A redirect URI must not carry a user name or password.';
		}

		if ( 'http' === $parts['scheme'] && ! self::loopback( $parts['host'] ) ) {
			return 'A redirect URI must use https, or http to localhost / 127.0.0.1 / [::1].';
		}

		return null;
	}

	/**
	 * Whether a presented redirect URI matches a registered one.
	 *
	 * Byte for byte, but for the port of a loopback URI.
	 *
	 * @since 1.0.0
	 *
	 * @param string $registered From the client's registration.
	 * @param string $presented  From the request.
	 *
	 * @return bool
	 */
	public static function redirect_matches( string $registered, string $presented ): bool {
		if ( hash_equals( $registered, $presented ) ) {
			return true;
		}

		$a = self::parts( $registered );
		$b = self::parts( $presented );

		if ( null === $a || null === $b || 'http' !== $a['scheme'] || ! self::loopback( $a['host'] ) ) {
			return false;
		}

		// Only the port may differ, and everything else must be the same
		// string it was registered as — the case of the path included.
		return hash_equals( self::without_port( $registered ), self::without_port( $presented ) );
	}

	/**
	 * Whether a host is this machine.
	 *
	 * @since 1.0.0
	 *
	 * @param string $host Host, IPv6 in brackets.
	 *
	 * @return bool
	 */
	public static function loopback( string $host ): bool {
		return in_array( strtolower( $host ), self::LOOPBACK, true );
	}

	/**
	 * A well-known URI for a resource or issuer (RFC 8414 §3.1, RFC 9728 §3.1).
	 *
	 * The suffix goes between the host and the path, so the issuer
	 * `https://a.example/tenant` has its metadata at
	 * `https://a.example/.well-known/oauth-authorization-server/tenant`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $suffix E.g. `oauth-protected-resource`.
	 * @param string $uri    The resource or issuer.
	 *
	 * @return string
	 *
	 * @throws \InvalidArgumentException When $uri is not an absolute URL.
	 */
	public static function well_known( string $suffix, string $uri ): string {
		$canonical = self::resource( $uri );
		$parts     = null === $canonical ? null : self::parts( $canonical );

		if ( null === $parts ) {
			throw new \InvalidArgumentException( 'A well-known URI is built from an absolute URL without a fragment.' );
		}

		return $parts['scheme'] . '://' . $parts['host'] . self::port( $parts ) . '/.well-known/' . $suffix . ( $parts['path'] ?? '' );
	}

	/**
	 * The origin of a URL: scheme, host and any non-default port.
	 *
	 * @since 1.0.0
	 *
	 * @param string $uri Absolute URL.
	 *
	 * @return string|null
	 */
	public static function origin( string $uri ): ?string {
		$parts = self::parts( $uri );

		return null === $parts ? null : $parts['scheme'] . '://' . $parts['host'] . self::port( $parts );
	}

	/**
	 * The host of a URL, for showing a person where a redirect goes.
	 *
	 * @since 1.0.0
	 *
	 * @param string $uri Absolute URL.
	 *
	 * @return string Empty when there is none.
	 */
	public static function host( string $uri ): string {
		return self::parts( $uri )['host'] ?? '';
	}

	/**
	 * A URL with these query parameters added, after any it already has.
	 *
	 * A redirect URI may carry its own query (OAuth 2.1 §2.3.1); ours is
	 * appended rather than replacing it.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $uri    Base URL.
	 * @param array<string, string> $params Parameters; empty strings are left out.
	 *
	 * @return string
	 */
	public static function with_query( string $uri, array $params ): string {
		$params = array_filter( $params, static fn ( string $value ): bool => '' !== $value );

		if ( array() === $params ) {
			return $uri;
		}

		return $uri . ( str_contains( $uri, '?' ) ? '&' : '?' ) . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 );
	}

	/**
	 * An absolute http(s) URL, parsed, scheme and host lowercased.
	 *
	 * @param string $uri Candidate.
	 *
	 * @return array{scheme: string, host: string, port?: int, path?: string, query?: string, fragment?: string, user?: string, pass?: string}|null
	 */
	private static function parts( string $uri ): ?array {
		if ( '' === $uri || 1 === preg_match( '/[\x00-\x20\x7f]/', $uri ) ) {
			return null;
		}

		$parts = parse_url( $uri );

		if ( ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) || '' === $parts['host'] ) {
			return null;
		}

		$parts['scheme'] = strtolower( $parts['scheme'] );
		$parts['host']   = strtolower( $parts['host'] );

		return in_array( $parts['scheme'], array( 'http', 'https' ), true ) ? $parts : null;
	}

	/**
	 * `:port`, or nothing for the scheme's default.
	 *
	 * @param array $parts From parts().
	 *
	 * @return string
	 */
	private static function port( array $parts ): string {
		if ( ! isset( $parts['port'] ) ) {
			return '';
		}

		$default = 'https' === $parts['scheme'] ? 443 : 80;

		return $default === (int) $parts['port'] ? '' : ':' . (int) $parts['port'];
	}

	/**
	 * A loopback URL with its port taken out, otherwise as written.
	 *
	 * @param string $uri Loopback URL.
	 *
	 * @return string
	 */
	private static function without_port( string $uri ): string {
		return (string) preg_replace( '#^(http://(?:\[[^\]]+\]|[^/:?]+)):\d+#i', '$1', $uri );
	}
}
