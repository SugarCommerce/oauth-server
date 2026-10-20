<?php
/**
 * An authorization code, as stored.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class Code
 *
 * Everything the token endpoint must check the code against, fixed at the
 * moment the person approved: who the client was, where the code was sent,
 * the PKCE challenge, the resource and the scopes. The code itself is never
 * stored — only its digest, as the key.
 *
 * @since 1.0.0
 */
final readonly class Code {

	/**
	 * @since 1.0.0
	 *
	 * @param string                $client_id    Who it was issued to.
	 * @param string                $redirect_uri Where it was sent, exactly.
	 * @param string                $challenge    The S256 code_challenge.
	 * @param string                $resource     The canonical resource.
	 * @param string[]              $scopes       What was approved, expanded.
	 * @param string                $subject      Whose authority it carries —
	 *                                            the application's id for the
	 *                                            person who approved.
	 * @param array<string, string> $context      Anything else the
	 *                                            application attaches to the
	 *                                            grant, e.g. an account.
	 * @param int                   $expires_at   Unix time.
	 * @param bool                  $spent        Whether it had been
	 *                                            exchanged before this look.
	 * @param string|null           $grant_id     The grant it became, once.
	 */
	public function __construct(
		public string $client_id,
		public string $redirect_uri,
		public string $challenge,
		public string $resource,
		public array $scopes,
		public string $subject,
		public array $context,
		public int $expires_at,
		public bool $spent = false,
		public ?string $grant_id = null,
	) {}
}
