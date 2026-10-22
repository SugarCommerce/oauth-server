<?php
/**
 * Where an authorization server is, what it protects, and for how long.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class Settings
 *
 * One authorization server protecting one resource — the shape the MCP
 * spec describes for a server that is its own authorization server. Both
 * metadata documents are built from here, so what is advertised and what
 * is enforced cannot disagree.
 *
 * Scopes are a map of name to the scopes it implies (`write` implies
 * `read`): MCP 2026-07-28 says a server MUST account for scope hierarchies
 * when deciding whether a token is enough, and expanding them once, at
 * issue, is the place that cannot be forgotten.
 *
 * @since 1.0.0
 */
final readonly class Settings {

	/**
	 * Validate and hold the configuration.
	 *
	 * @since 1.0.0
	 *
	 * @param string                  $issuer        The issuer identifier: an
	 *                                               https URL without query
	 *                                               or fragment.
	 * @param string                  $resource      The protected resource —
	 *                                               the MCP endpoint's
	 *                                               canonical URL.
	 * @param string                  $authorization_endpoint Where a person
	 *                                               signs in and decides.
	 * @param string                  $token_endpoint         Token endpoint.
	 * @param string                  $revocation_endpoint    RFC 7009.
	 * @param string                  $registration_endpoint  RFC 7591, or ''
	 *                                               for none.
	 * @param array<string, string[]> $scopes        Each scope, and the scopes
	 *                                               it implies.
	 * @param string                  $resource_name Shown by clients.
	 * @param string                  $documentation A page for developers, or ''.
	 * @param bool                    $documents     Accept Client ID Metadata
	 *                                               Documents.
	 * @param int                     $access_ttl    Access token lifetime.
	 * @param int                     $refresh_ttl   Each refresh token's
	 *                                               lifetime; rotation gives
	 *                                               a fresh one each use.
	 * @param int                     $code_ttl      Authorization code lifetime.
	 * @param string                  $access_prefix  Before an access token, so
	 *                                               one pasted somewhere it
	 *                                               should not be is
	 *                                               recognisable (and found
	 *                                               by secret scanners).
	 * @param string                  $refresh_prefix The same for refresh tokens.
	 *
	 * @throws \InvalidArgumentException When the issuer or resource is not a
	 *                                   URL, or a lifetime is not positive.
	 */
	public function __construct(
		public string $issuer,
		public string $resource,
		public string $authorization_endpoint,
		public string $token_endpoint,
		public string $revocation_endpoint,
		public string $registration_endpoint = '',
		public array $scopes = array(),
		public string $resource_name = '',
		public string $documentation = '',
		public bool $documents = true,
		public int $access_ttl = 3600,
		public int $refresh_ttl = 2_592_000,
		public int $code_ttl = 60,
		public string $access_prefix = 'oat',
		public string $refresh_prefix = 'ort',
	) {
		if ( null === Uri::origin( $issuer ) || str_contains( $issuer, '?' ) || str_contains( $issuer, '#' ) ) {
			throw new \InvalidArgumentException( 'The issuer is an absolute URL with no query or fragment.' );
		}

		if ( null === Uri::resource( $resource ) ) {
			throw new \InvalidArgumentException( 'The resource is an absolute URL with no fragment.' );
		}

		if ( $access_ttl < 1 || $refresh_ttl < 1 || $code_ttl < 1 ) {
			throw new \InvalidArgumentException( 'Lifetimes are at least a second.' );
		}
	}

	/**
	 * Every scope name.
	 *
	 * @since 1.0.0
	 *
	 * @return string[]
	 */
	public function scope_names(): array {
		return array_keys( $this->scopes );
	}

	/**
	 * Known scopes from a space-separated list, with what they imply.
	 *
	 * Unknown ones are dropped (RFC 6749 §3.3 lets the server ignore part
	 * of a request), so a client that adds `openid` or `offline_access` is
	 * not refused for it.
	 *
	 * @since 1.0.0
	 *
	 * @param string|string[] $scope Requested.
	 *
	 * @return string[] In the order the settings list them.
	 */
	public function expand( string|array $scope ): array {
		$asked = is_array( $scope ) ? $scope : ( preg_split( '/ +/', trim( $scope ), -1, PREG_SPLIT_NO_EMPTY ) ?: array() );
		$held  = array();

		foreach ( $asked as $name ) {
			if ( isset( $this->scopes[ $name ] ) ) {
				$held[] = $name;
				$held   = array_merge( $held, $this->scopes[ $name ] );
			}
		}

		return array_values( array_intersect( $this->scope_names(), $held ) );
	}

	/**
	 * Where the protected resource metadata is (RFC 9728 §3.1).
	 *
	 * The path-inserted form, which is what a 401's `resource_metadata`
	 * points at. Serve the same document at the root too: clients that
	 * construct the URL themselves try both (MCP 2026-07-28, "Protected
	 * Resource Metadata Discovery Requirements").
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function resource_metadata_url(): string {
		return Uri::well_known( 'oauth-protected-resource', $this->resource );
	}

	/**
	 * Where the authorization server metadata is (RFC 8414 §3.1).
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function server_metadata_url(): string {
		return Uri::well_known( 'oauth-authorization-server', $this->issuer );
	}

	/**
	 * The protected resource metadata document (RFC 9728 §2).
	 *
	 * `scopes_supported` is what a client asks for when the challenge names
	 * none. No `offline_access`: MCP says a resource SHOULD NOT advertise
	 * it, since refresh tokens are the authorization server's business.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, mixed>
	 */
	public function resource_metadata(): array {
		return array_filter( array(
			'resource'                 => Uri::resource( $this->resource ),
			'authorization_servers'    => array( $this->issuer ),
			'scopes_supported'         => $this->scope_names(),
			'bearer_methods_supported' => array( 'header' ),
			'resource_name'            => $this->resource_name,
			'resource_documentation'   => $this->documentation,
		), static fn ( mixed $value ): bool => '' !== $value && array() !== $value );
	}

	/**
	 * The authorization server metadata document (RFC 8414 §2).
	 *
	 * What each field promises, since every one is a promise a client acts
	 * on:
	 *
	 * - `code_challenge_methods_supported: ["S256"]` — an MCP client MUST
	 *   refuse a server without it, and `plain` is not offered.
	 * - `token_endpoint_auth_methods_supported: ["none"]` — public clients;
	 *   Claude uses a metadata document only when `none` is listed.
	 * - `authorization_response_iss_parameter_supported` — RFC 9207, against
	 *   mix-up attacks; ChatGPT uses its stable client id only when it is set.
	 * - `client_id_metadata_document_supported` — CIMD, preferred by MCP.
	 * - `registration_endpoint` — RFC 7591, kept for clients that predate CIMD.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, mixed>
	 */
	public function server_metadata(): array {
		return array_filter( array(
			'issuer'                                         => $this->issuer,
			'authorization_endpoint'                         => $this->authorization_endpoint,
			'token_endpoint'                                 => $this->token_endpoint,
			'revocation_endpoint'                            => $this->revocation_endpoint,
			'registration_endpoint'                          => $this->registration_endpoint,
			'scopes_supported'                               => $this->scope_names(),
			'response_types_supported'                       => array( 'code' ),
			'response_modes_supported'                       => array( 'query' ),
			'grant_types_supported'                          => array( 'authorization_code', 'refresh_token' ),
			'token_endpoint_auth_methods_supported'          => array( 'none' ),
			'revocation_endpoint_auth_methods_supported'     => array( 'none' ),
			'code_challenge_methods_supported'               => array( 'S256' ),
			'authorization_response_iss_parameter_supported' => true,
			'client_id_metadata_document_supported'          => $this->documents,
			'service_documentation'                          => $this->documentation,
		), static fn ( mixed $value ): bool => '' !== $value && array() !== $value && false !== $value );
	}
}
