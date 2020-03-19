/**
 * Bit manipulation utility module.
 *
 * This (will) include bit swapping functions, and some extras (such as the
 * BIT template to help selecting bits).
 *
 * License: BSD 3-Clause
 */
module utils.bit;

/// Create a 1-bit bitmask with a bit position (LSB, 0-based, 1 << a).
template BIT(int n) { enum { BIT = 1 << n } }