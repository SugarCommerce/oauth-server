<?php
/**
 * An authorization request that passed every check.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class AuthorizationRequest
 *
 * What a consent screen draws, and what approve() or deny() needs. The
 * request is checked again when the person answers — the consent form posts
 * the original parameters back rather than a handle to a stored copy — so
 * nothing about it lives on the server between the two.
 *
 * @since 1.0.0
 */
final readonly class AuthorizationRequest {

	/**
	 * Hold a request that passed every check.
	 *
	 * @since 1.0.0
	 *
	 * @param Client   $client       The client, validated.
	 * @param string   $redirect_uri As presented; it matched a registered one.
	 * @param string   $state        Passed back untouched; '' when absent.
	 * @param string   $challenge    S256 code_challenge.
	 * @param string   $resource     Canonical resource.
	 * @param string[] $scopes       Asked for, known, expanded.
	 * @param array<string, string> $params The query, to post back.
	 */
	public function __construct(
		public Client $client,
		public string $redirect_uri,
		public string $state,
		public string $challenge,
		public string $resource,
		public array $scopes,
		public array $params,
	) {}

	/**
	 * Where the code would be sent, for showing the person plainly.
	 *
	 * MCP 2026-07-28 ("Localhost Redirect URI Risks"): the server MUST show
	 * the redirect URI's host during authorization.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function redirect_host(): string {
		return Uri::host( $this->redirect_uri );
	}
}
