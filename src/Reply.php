<?php
/**
 * What an endpoint answers.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Class Reply
 *
 * A status, a JSON body and headers, for the application to send through
 * its own response object — this library writes nothing to output.
 *
 * Every reply is `no-store`: a token response must never be cached (OAuth
 * 2.1 §3.2.3), and an error or a registration is no better in a proxy.
 *
 * @since 1.0.0
 */
final readonly class Reply {

	/**
	 * Build a reply.
	 *
	 * @since 1.0.0
	 *
	 * @param int                   $status  HTTP status.
	 * @param array<string, mixed>  $body    Encoded as JSON.
	 * @param array<string, string> $headers Beyond the defaults.
	 */
	public function __construct(
		public int $status,
		public array $body,
		private array $headers = array(),
	) {}

	/**
	 * The headers to send.
	 *
	 * @since 1.0.0
	 *
	 * @return array<string, string>
	 */
	public function headers(): array {
		return $this->headers + array(
			'Content-Type'  => 'application/json',
			'Cache-Control' => 'no-store',
			'Pragma'        => 'no-cache',
		);
	}

	/**
	 * The body as JSON. An empty body is `{}`, not `[]`.
	 *
	 * Invalid UTF-8 is replaced rather than failing the whole encode, so a
	 * reply is never an empty string.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function json(): string {
		return (string) json_encode( array() === $this->body ? new \stdClass() : $this->body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE );
	}
}
