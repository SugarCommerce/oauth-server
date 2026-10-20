<?php
/**
 * A Store in arrays, for the tests.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer\Tests;

use SugarCommerce\OAuthServer\{Client, Code, Grant, Store, StoredToken};

/**
 * Class MemoryStore
 *
 * The contract an application's tables must keep, kept in memory: spending
 * is check-and-set in one step, and revoking a grant ends its tokens.
 */
final class MemoryStore implements Store {

	/** @var array<string, Client> */
	public array $clients = array();

	/** @var array<string, Code> */
	public array $codes = array();

	/** @var array<string, Grant> */
	public array $grants = array();

	/** @var array<string, StoredToken> */
	public array $tokens = array();

	/** @var array<string, string> Grant id => why it was revoked. */
	public array $revoked = array();

	/**
	 * Find a client.
	 *
	 * @param string $id Id.
	 *
	 * @return Client|null
	 */
	public function find_client( string $id ): ?Client {
		return $this->clients[ $id ] ?? null;
	}

	/**
	 * Save a client.
	 *
	 * @param Client $client Client.
	 * @param int    $now    Time.
	 *
	 * @return void
	 */
	public function save_client( Client $client, int $now ): void {
		$this->clients[ $client->id ] = $client;
	}

	/**
	 * Save a code.
	 *
	 * @param string $hash Digest.
	 * @param Code   $code Code.
	 *
	 * @return void
	 */
	public function save_code( string $hash, Code $code ): void {
		$this->codes[ $hash ] = $code;
	}

	/**
	 * Spend a code.
	 *
	 * @param string $hash Digest.
	 * @param int    $now  Time.
	 *
	 * @return Code|null
	 */
	public function spend_code( string $hash, int $now ): ?Code {
		$code = $this->codes[ $hash ] ?? null;

		if ( null === $code ) {
			return null;
		}

		$this->codes[ $hash ] = self::with( $code, array( 'spent' => true ) );

		return $code;
	}

	/**
	 * Make a grant.
	 *
	 * @param string $code_hash Digest.
	 * @param Code   $code      Code.
	 * @param Client $client    Client.
	 * @param int    $now       Time.
	 *
	 * @return string
	 */
	public function create_grant( string $code_hash, Code $code, Client $client, int $now ): string {
		$id = 'g' . ( count( $this->grants ) + 1 );

		$this->grants[ $id ]      = new Grant( $id, $code->client_id, $code->scopes, $code->resource, $code->subject, $code->context, true, $client->name );
		$this->codes[ $code_hash ] = self::with( $this->codes[ $code_hash ], array( 'grant_id' => $id ) );

		return $id;
	}

	/**
	 * Find a grant.
	 *
	 * @param string $id Id.
	 *
	 * @return Grant|null
	 */
	public function find_grant( string $id ): ?Grant {
		return $this->grants[ $id ] ?? null;
	}

	/**
	 * Revoke a grant and its tokens.
	 *
	 * @param string $id     Id.
	 * @param string $reason Why.
	 * @param int    $now    Time.
	 *
	 * @return bool
	 */
	public function revoke_grant( string $id, string $reason, int $now ): bool {
		$grant = $this->grants[ $id ] ?? null;

		if ( null === $grant || ! $grant->active ) {
			return false;
		}

		$this->grants[ $id ]  = self::with( $grant, array( 'active' => false ) );
		$this->revoked[ $id ] = $reason;
		$this->tokens         = array_filter( $this->tokens, static fn ( StoredToken $t ): bool => $t->grant_id !== $id );

		return true;
	}

	/**
	 * Note a use.
	 *
	 * @param string $id  Id.
	 * @param int    $now Time.
	 *
	 * @return void
	 */
	public function touch_grant( string $id, int $now ): void {}

	/**
	 * Save a token.
	 *
	 * @param string      $hash  Digest.
	 * @param StoredToken $token Token.
	 * @param int         $now   Time.
	 *
	 * @return void
	 */
	public function save_token( string $hash, StoredToken $token, int $now ): void {
		$this->tokens[ $hash ] = $token;
	}

	/**
	 * Find a token.
	 *
	 * @param string $hash Digest.
	 *
	 * @return StoredToken|null
	 */
	public function find_token( string $hash ): ?StoredToken {
		return $this->tokens[ $hash ] ?? null;
	}

	/**
	 * Spend a refresh token.
	 *
	 * @param string $hash Digest.
	 * @param int    $now  Time.
	 *
	 * @return bool
	 */
	public function spend_refresh( string $hash, int $now ): bool {
		$token = $this->tokens[ $hash ] ?? null;

		if ( null === $token || $token->spent ) {
			return false;
		}

		$this->tokens[ $hash ] = self::with( $token, array( 'spent' => true ) );

		return true;
	}

	/**
	 * Delete a token.
	 *
	 * @param string $hash Digest.
	 *
	 * @return void
	 */
	public function delete_token( string $hash ): void {
		unset( $this->tokens[ $hash ] );
	}

	/**
	 * A copy with some properties changed.
	 *
	 * Not clone-with: these are readonly, settable only from their own class.
	 *
	 * @template T of object
	 *
	 * @param T     $object  Original.
	 * @param array $changes Property => value.
	 *
	 * @return T
	 */
	private static function with( object $object, array $changes ): object {
		return new ( $object::class )( ...array_merge( get_object_vars( $object ), $changes ) );
	}
}
