<?php
/**
 * Where the authorization server keeps its state.
 *
 * @package   SugarCommerce\OAuthServer
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuthServer;

/**
 * Interface Store
 *
 * The application's tables, behind the operations the protocol needs. An
 * interface because where they live, and what else a grant is tied to, is
 * the application's business.
 *
 * Two operations MUST be atomic, because each is what stops a stolen
 * credential being used twice by two racing requests: spend_code() and
 * spend_refresh(). In SQL that is one conditional UPDATE whose affected-row
 * count is the answer, never a read followed by a write.
 *
 * And a code's replay must reach the grant it became even when the replay
 * arrives first: spend_code() marks a spent code as replayed, and
 * create_grant() refuses to record a grant against a code so marked. Each
 * is one atomic step, so whichever lands second sees the other.
 *
 * Every token and code arrives as its digest; the store never sees one.
 *
 * @since 1.0.0
 */
interface Store {

	/**
	 * A client by id, or null.
	 *
	 * @since 1.0.0
	 *
	 * @param string $id client_id.
	 *
	 * @return Client|null A metadata-document client even when its copy has
	 *                     expired; the server decides whether to refetch.
	 */
	public function find_client( string $id ): ?Client;

	/**
	 * Store a client, replacing one with the same id.
	 *
	 * @since 1.0.0
	 *
	 * @param Client $client The client.
	 * @param int    $now    Unix time.
	 *
	 * @return void
	 */
	public function save_client( Client $client, int $now ): void;

	/**
	 * Store a new authorization code.
	 *
	 * @since 1.0.0
	 *
	 * @param string $hash Digest of the code.
	 * @param Code   $code What it is for.
	 *
	 * @return void
	 */
	public function save_code( string $hash, Code $code ): void;

	/**
	 * Mark a code exchanged, atomically, and return it.
	 *
	 * A code that was already spent is a replay. In the same atomic step
	 * the store marks it replayed and reads the grant it became, so the
	 * exchange still under way — spent, its grant not yet recorded — finds
	 * the mark when it comes to create_grant(), and makes nothing.
	 *
	 * @since 1.0.0
	 * @since 1.1.0 Marks a replayed code, for create_grant().
	 *
	 * @param string $hash Digest of the code.
	 * @param int    $now  Unix time.
	 *
	 * @return Code|null Null when no such code. `spent` is true when it had
	 *                   already been exchanged — a replay — with the
	 *                   `grant_id` it became, or null when none is
	 *                   recorded yet.
	 */
	public function spend_code( string $hash, int $now ): ?Code;

	/**
	 * Make the grant a code is exchanged for, and remember which it was —
	 * unless the code was presented again since it was spent.
	 *
	 * Atomic: the grant is made and recorded against the code only if
	 * spend_code() has not marked the code replayed; otherwise nothing is
	 * made. In SQL, the grant's INSERT and a conditional UPDATE of the code
	 * in one transaction, rolled back when the UPDATE changes nothing.
	 *
	 * @since 1.0.0
	 * @since 1.1.0 Returns null for a code replayed before its grant existed.
	 *
	 * @param string $code_hash Digest of the code.
	 * @param Code   $code      The code.
	 * @param Client $client    Its client, for the name to show.
	 * @param int    $now       Unix time.
	 *
	 * @return string|null Grant id, or null when the code was replayed.
	 */
	public function create_grant( string $code_hash, Code $code, Client $client, int $now ): ?string;

	/**
	 * A grant by id, or null.
	 *
	 * @since 1.0.0
	 *
	 * @param string $id Grant id.
	 *
	 * @return Grant|null
	 */
	public function find_grant( string $id ): ?Grant;

	/**
	 * End a grant and every token made from it.
	 *
	 * @since 1.0.0
	 *
	 * @param string $id     Grant id.
	 * @param string $reason Why: e.g. `refresh_reused`, `code_reused`, `client`.
	 * @param int    $now    Unix time.
	 *
	 * @return bool Whether it was active until now.
	 */
	public function revoke_grant( string $id, string $reason, int $now ): bool;

	/**
	 * Note that a grant was used.
	 *
	 * @since 1.0.0
	 *
	 * @param string $id  Grant id.
	 * @param int    $now Unix time.
	 *
	 * @return void
	 */
	public function touch_grant( string $id, int $now ): void;

	/**
	 * Store a new token.
	 *
	 * @since 1.0.0
	 *
	 * @param string      $hash  Digest of the token.
	 * @param StoredToken $token What it is.
	 * @param int         $now   Unix time.
	 *
	 * @return void
	 */
	public function save_token( string $hash, StoredToken $token, int $now ): void;

	/**
	 * A token by digest, or null.
	 *
	 * @since 1.0.0
	 *
	 * @param string $hash Digest.
	 *
	 * @return StoredToken|null
	 */
	public function find_token( string $hash ): ?StoredToken;

	/**
	 * Mark a refresh token exchanged, atomically.
	 *
	 * @since 1.0.0
	 *
	 * @param string $hash Digest.
	 * @param int    $now  Unix time.
	 *
	 * @return bool True when it was unspent until now; false when somebody
	 *              else spent it first.
	 */
	public function spend_refresh( string $hash, int $now ): bool;

	/**
	 * Delete one token.
	 *
	 * @since 1.0.0
	 *
	 * @param string $hash Digest.
	 *
	 * @return void
	 */
	public function delete_token( string $hash ): void;
}
