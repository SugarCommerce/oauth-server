<?php
/**
 * An access or refresh token, as stored.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class StoredToken
 *
 * Opaque tokens, stored as a SHA-256 digest and looked up by it: a copy of
 * the database hands out nothing usable, and a token cannot be read back
 * even by us. Opaque rather than a JWT because every request is checked
 * against the store anyway — revocation has to take effect at once, which
 * a self-contained token cannot do — so a signature would only add a key
 * to keep.
 *
 * @since 1.0.0
 */
final readonly class StoredToken {

	/**
	 * The kind of a bearer token, presented to the resource.
	 */
	public const string ACCESS = 'access';

	/**
	 * The kind of a token exchanged at the token endpoint for new ones.
	 */
	public const string REFRESH = 'refresh';

	/**
	 * Describe a stored token.
	 *
	 * @since 1.0.0
	 *
	 * @param string   $grant_id   The grant it belongs to.
	 * @param string   $kind       ACCESS or REFRESH.
	 * @param string[] $scopes     What it carries — an access token may hold
	 *                             fewer than its grant.
	 * @param int      $expires_at Unix time.
	 * @param bool     $spent      A refresh token already exchanged.
	 */
	public function __construct(
		public string $grant_id,
		public string $kind,
		public array $scopes,
		public int $expires_at,
		public bool $spent = false,
	) {}
}
