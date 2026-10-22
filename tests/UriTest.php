<?php
/**
 * URI rules.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\OAuthServer\Uri;

/**
 * Class UriTest
 */
final class UriTest extends TestCase {

	/**
	 * @return array<string, array{0: string, 1: string|null}>
	 */
	public static function resources(): array {
		return array(
			'already canonical'     => array( 'https://mcp.example.com/mcp', 'https://mcp.example.com/mcp' ),
			'uppercase scheme/host' => array( 'HTTPS://MCP.Example.COM/mcp', 'https://mcp.example.com/mcp' ),
			'trailing slash'        => array( 'https://mcp.example.com/mcp/', 'https://mcp.example.com/mcp' ),
			'bare host slash'       => array( 'https://mcp.example.com/', 'https://mcp.example.com' ),
			'default port'          => array( 'https://mcp.example.com:443/mcp', 'https://mcp.example.com/mcp' ),
			'other port kept'       => array( 'https://mcp.example.com:8443', 'https://mcp.example.com:8443' ),
			'path case kept'        => array( 'https://mcp.example.com/MCP', 'https://mcp.example.com/MCP' ),
			'no scheme'             => array( 'mcp.example.com', null ),
			'fragment'              => array( 'https://mcp.example.com#x', null ),
			'user info'             => array( 'https://a@mcp.example.com/', null ),
			'not http'              => array( 'ftp://mcp.example.com/', null ),
		);
	}

	#[DataProvider( 'resources' )]
	public function test_a_resource_has_one_canonical_form( string $given, ?string $canonical ): void {
		$this->assertSame( $canonical, Uri::resource( $given ) );
	}

	public function test_resources_compare_in_canonical_form(): void {
		$this->assertTrue( Uri::same_resource( 'https://API.example.com/mcp/', 'https://api.example.com/mcp' ) );
		$this->assertFalse( Uri::same_resource( 'https://api.example.com/mcp', 'https://api.example.com/other' ) );
		$this->assertFalse( Uri::same_resource( 'https://api.example.com/mcp', 'https://evil.example/mcp' ) );
		$this->assertFalse( Uri::same_resource( 'nonsense', 'nonsense' ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function redirects(): array {
		return array(
			'https'              => array( 'https://claude.ai/api/mcp/auth_callback', true ),
			'https with query'   => array( 'https://app.example.com/cb?x=1', true ),
			'loopback ip'        => array( 'http://127.0.0.1:3000/callback', true ),
			'loopback v6'        => array( 'http://[::1]/callback', true ),
			'localhost'          => array( 'http://localhost:8080/callback', true ),
			'plain http'         => array( 'http://app.example.com/cb', false ),
			'fragment'           => array( 'https://app.example.com/cb#frag', false ),
			'user info'          => array( 'https://good.example@evil.example/cb', false ),
			'custom scheme'      => array( 'myapp://callback', false ),
			'javascript'         => array( 'javascript:alert(1)', false ),
			'relative'           => array( '/cb', false ),
			'space'              => array( 'https://app.example.com/c b', false ),
			'localhost lookalike' => array( 'http://localhost.evil.example/cb', false ),
			// PHP reads the host as `evil.example\good.example`; a browser goes to evil.example.
			'backslash'          => array( 'https://evil.example\\good.example/cb', false ),
			'backslash in path'  => array( 'https://app.example.com/cb\\..\\x', false ),
		);
	}

	#[DataProvider( 'redirects' )]
	public function test_only_https_or_loopback_may_be_a_redirect( string $uri, bool $allowed ): void {
		$this->assertSame( $allowed, null === Uri::redirect_problem( $uri ) );
	}

	public function test_redirects_match_exactly(): void {
		$this->assertTrue( Uri::redirect_matches( 'https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback' ) );
		$this->assertFalse( Uri::redirect_matches( 'https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback/' ) );
		$this->assertFalse( Uri::redirect_matches( 'https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback?x=1' ) );
		$this->assertFalse( Uri::redirect_matches( 'https://claude.ai/cb', 'https://CLAUDE.ai/cb' ) );
		$this->assertFalse( Uri::redirect_matches( 'https://app.example.com:443/cb', 'https://app.example.com:8443/cb' ) );
	}

	/**
	 * OAuth 2.1 §8.4.2: any port on a loopback redirect, nothing else loose.
	 */
	public function test_a_loopback_redirect_may_use_any_port(): void {
		$this->assertTrue( Uri::redirect_matches( 'http://127.0.0.1/callback', 'http://127.0.0.1:53124/callback' ) );
		$this->assertTrue( Uri::redirect_matches( 'http://localhost:3000/callback', 'http://localhost:4000/callback' ) );
		$this->assertTrue( Uri::redirect_matches( 'http://[::1]/callback', 'http://[::1]:9000/callback' ) );
		$this->assertFalse( Uri::redirect_matches( 'http://127.0.0.1/callback', 'http://127.0.0.1:53124/other' ) );
		$this->assertFalse( Uri::redirect_matches( 'http://127.0.0.1/callback', 'http://localhost:53124/callback' ) );
	}

	public function test_well_known_uris_insert_the_suffix_before_the_path(): void {
		$this->assertSame( 'https://api.example.com/.well-known/oauth-protected-resource/mcp', Uri::well_known( 'oauth-protected-resource', 'https://api.example.com/mcp' ) );
		$this->assertSame( 'https://api.example.com/.well-known/oauth-authorization-server', Uri::well_known( 'oauth-authorization-server', 'https://api.example.com' ) );
		$this->assertSame( 'http://127.0.0.1:8099/.well-known/oauth-protected-resource/api/mcp', Uri::well_known( 'oauth-protected-resource', 'http://127.0.0.1:8099/api/mcp' ) );
	}

	public function test_query_parameters_are_added_after_the_redirects_own(): void {
		$this->assertSame( 'https://a.example/cb?x=1&code=abc&state=s%20t', Uri::with_query( 'https://a.example/cb?x=1', array( 'code' => 'abc', 'state' => 's t', 'empty' => '' ) ) );
		$this->assertSame( 'https://a.example/cb', Uri::with_query( 'https://a.example/cb', array( 'state' => '' ) ) );
	}

	public function test_hosts_and_origins(): void {
		$this->assertSame( 'claude.ai', Uri::host( 'https://claude.ai/api/mcp/auth_callback' ) );
		$this->assertSame( 'https://api.example.com', Uri::origin( 'https://API.example.com:443/mcp' ) );
		$this->assertTrue( Uri::loopback( 'LOCALHOST' ) );
		$this->assertFalse( Uri::loopback( '127.0.0.2' ) );
	}
}
