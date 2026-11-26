/**
 * GOTU Password Hashing
 * Uses Argon2id with OWASP-recommended parameters.
 */

import argon2 from 'argon2';

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,   // 64 MiB
  timeCost:   3,       // 3 iterations
  parallelism: 1,
};

/**
 * Hash a password using Argon2id.
 * @param {string} password - plaintext password
 * @returns {Promise<string>} Argon2 hash string
 */
export async function hashPassword(password) {
  return argon2.hash(password, ARGON2_OPTIONS);
}

/**
 * Verify a password against a stored Argon2id hash.
 * @param {string} hash - stored hash
 * @param {string} password - plaintext candidate
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(hash, password) {
  return argon2.verify(hash, password);
}
