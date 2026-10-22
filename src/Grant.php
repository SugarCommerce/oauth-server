<?php
/**
 * A person's approval of one client.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class Grant
 *
 * The unit of revocation. Every token traces back to one grant, and
 * revoking it — the person disconnecting, a refresh token or a code used
 * twice — ends every token made from it at once.
 *
 * @since 1.0.0
 */
final readonly class Grant {

	/**
	 * Describe a grant.
	 *
	 * @since 1.0.0
	 *
	 * @param string                $id        Grant id.
	 * @param string                $client_id Client.
	 * @param string[]              $scopes    Approved, expanded.
	 * @param string                $resource  Canonical resource.
	 * @param string                $subject   Whose authority.
	 * @param array<string, string> $context   What the application attached.
	 * @param bool                  $active    False once revoked.
	 * @param string                $client_name The client's name when approved.
	 */
	public function __construct(
		public string $id,
		public string $client_id,
		public array $scopes,
		public string $resource,
		public string $subject,
		public array $context = array(),
		public bool $active = true,
		public string $client_name = '',
	) {}
}
