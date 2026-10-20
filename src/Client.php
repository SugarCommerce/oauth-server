<?php
/**
 * A client the authorization server knows.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class Client
 *
 * Always a public client (`token_endpoint_auth_method: none`). An MCP
 * client is a desktop app, a CLI, or a hosted assistant registering itself
 * on the fly; none of them can keep a secret we would hand out to anybody
 * who asks, so a secret would protect nothing that PKCE and an exact
 * redirect URI do not already. OAuth 2.1 §2.1 lets an authorization server
 * treat every dynamically registered client this way, and MCP's own
 * clients (Claude, ChatGPT, Claude Code) all speak it.
 *
 * Two origins: registered through RFC 7591 (`document` false, an id we
 * made) or described by a Client ID Metadata Document (`document` true, the
 * id is the document's URL, and the copy we hold expires so a change to the
 * document is picked up).
 *
 * @since 1.0.0
 */
final readonly class Client {

	/**
	 * @since 1.0.0
	 *
	 * @param string   $id            client_id.
	 * @param string   $name          What it calls itself; may be empty for a
	 *                                registered client. Never trusted as
	 *                                proof of who it is.
	 * @param string[] $redirect_uris Registered, exactly as given.
	 * @param string[] $grant_types   Of authorization_code and refresh_token.
	 * @param bool     $document      Whether the id is a metadata document URL.
	 * @param string   $uri           Its client_uri, https only, or ''.
	 * @param int|null $expires_at    When a document's copy goes stale.
	 */
	public function __construct(
		public string $id,
		public string $name,
		public array $redirect_uris,
		public array $grant_types = array( 'authorization_code' ),
		public bool $document = false,
		public string $uri = '',
		public ?int $expires_at = null,
	) {}

	/**
	 * Whether a presented redirect URI is one of this client's.
	 *
	 * @since 1.0.0
	 *
	 * @param string $uri From the request.
	 *
	 * @return bool
	 */
	public function allows_redirect( string $uri ): bool {
		foreach ( $this->redirect_uris as $registered ) {
			if ( Uri::redirect_matches( $registered, $uri ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether it may use refresh tokens.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function refreshes(): bool {
		return in_array( 'refresh_token', $this->grant_types, true );
	}

	/**
	 * Whether every redirect URI is this machine's loopback.
	 *
	 * A loopback redirect proves nothing about who the client is: anything
	 * running on the person's computer can listen there, and can claim any
	 * name. The MCP spec asks for an extra warning on the consent screen.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function local_only(): bool {
		foreach ( $this->redirect_uris as $uri ) {
			if ( ! Uri::loopback( Uri::host( $uri ) ) ) {
				return false;
			}
		}

		return array() !== $this->redirect_uris;
	}

	/**
	 * The registration response (RFC 7591 §3.2.1).
	 *
	 * @since 1.0.0
	 *
	 * @param int $issued_at When the id was made.
	 *
	 * @return array<string, mixed>
	 */
	public function registration( int $issued_at ): array {
		return array_filter( array(
			'client_id'                  => $this->id,
			'client_id_issued_at'        => $issued_at,
			'client_name'                => $this->name,
			'client_uri'                 => $this->uri,
			'redirect_uris'              => $this->redirect_uris,
			'grant_types'                => $this->grant_types,
			'response_types'             => array( 'code' ),
			'token_endpoint_auth_method' => 'none',
		), static fn ( mixed $value ): bool => '' !== $value );
	}
}
