<?php
/**
 * An OAuth error, as the spec names it.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class OAuthError
 *
 * The `error` codes are the registered ones (OAuth 2.1 §4.1.2.1 and §3.2.4,
 * RFC 7591 §3.2.2, RFC 8707 §2), so a client can act on them; the
 * description is a sentence for the developer reading the log.
 *
 * `redirect` is the decision that matters most on the authorization
 * endpoint. Until the client and its redirect URI are known good, an error
 * is shown to the person in the browser and NEVER sent to the redirect URI —
 * otherwise the endpoint is an open redirector for anybody who invents a
 * client_id (OAuth 2.1 §4.1.2.1, RFC 9700 §4.11).
 *
 * @since 1.0.0
 */
final readonly class OAuthError {

	/**
	 * Name an error.
	 *
	 * @since 1.0.0
	 *
	 * @param string $error       Registered error code.
	 * @param string $description What was wrong, for a developer.
	 * @param int    $status      HTTP status, for the token, registration and
	 *                            revocation endpoints.
	 * @param bool   $redirect    Whether an authorization error may be sent to
	 *                            the client's redirect URI.
	 */
	public function __construct(
		public string $error,
		public string $description,
		public int $status = 400,
		public bool $redirect = false,
	) {}

	/**
	 * The JSON body (OAuth 2.1 §3.2.4).
	 *
	 * @since 1.0.0
	 *
	 * @return array{error: string, error_description: string}
	 */
	public function to_array(): array {
		return array( 'error' => $this->error, 'error_description' => $this->description );
	}

	/**
	 * As a reply from the token, registration or revocation endpoint.
	 *
	 * `invalid_client` carries the challenge RFC 6749 §5.2 asks for.
	 *
	 * @since 1.0.0
	 *
	 * @return Reply
	 */
	public function reply(): Reply {
		return new Reply( $this->status, $this->to_array(), 401 === $this->status ? array( 'WWW-Authenticate' => 'Basic realm="oauth"' ) : array() );
	}
}
