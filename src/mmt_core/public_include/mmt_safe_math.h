#ifndef MMT_SAFE_MATH_H
#define MMT_SAFE_MATH_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/**
 * Safe addition for uint32_t
 * @param a First operand
 * @param b Second operand
 * @param result Pointer to store result
 * @return true if successful, false if overflow would occur
 */
static inline bool mmt_safe_add_u32(uint32_t a, uint32_t b, uint32_t *result)
{
	if (UINT32_MAX - a < b) {
		return false;  // Overflow would occur
	}
	*result = a + b;
	return true;
}

/**
 * Safe multiplication for uint32_t
 * @param a First operand
 * @param b Second operand
 * @param result Pointer to store result
 * @return true if successful, false if overflow would occur
 */
static inline bool mmt_safe_mul_u32(uint32_t a, uint32_t b, uint32_t *result)
{
	if (a != 0 && b > UINT32_MAX / a) {
		return false;  // Overflow would occur
	}
	*result = a * b;
	return true;
}

/**
 * Safe addition for uint16_t
 * @param a First operand
 * @param b Second operand
 * @param result Pointer to store result
 * @return true if successful, false if overflow would occur
 */
static inline bool mmt_safe_add_u16(uint16_t a, uint16_t b, uint16_t *result)
{
	if (UINT16_MAX - a < b) {
		return false;
	}
	*result = a + b;
	return true;
}

/**
 * Safe left shift for uint16_t
 * @param value Value to shift
 * @param shift Number of bits to shift
 * @param result Pointer to store result
 * @return true if successful, false if overflow would occur
 */
static inline bool mmt_safe_shl_u16(uint16_t value, unsigned int shift, uint16_t *result)
{
	if (shift >= 16 || (shift > 0 && value > (UINT16_MAX >> shift))) {
		return false;  // Would overflow
	}
	*result = value << shift;
	return true;
}

/**
 * Safe left shift for uint32_t
 * @param value Value to shift
 * @param shift Number of bits to shift
 * @param result Pointer to store result
 * @return true if successful, false if overflow would occur
 */
static inline bool mmt_safe_shl_u32(uint32_t value, unsigned int shift, uint32_t *result)
{
	if (shift >= 32 || (shift > 0 && value > (UINT32_MAX >> shift))) {
		return false;  // Would overflow
	}
	*result = value << shift;
	return true;
}

/**
 * Safe subtraction for uint32_t
 * @param a First operand (minuend)
 * @param b Second operand (subtrahend)
 * @param result Pointer to store result
 * @return true if successful, false if underflow would occur
 */
static inline bool mmt_safe_sub_u32(uint32_t a, uint32_t b, uint32_t *result)
{
	if (a < b) {
		return false;  // Underflow would occur
	}
	*result = a - b;
	return true;
}

#endif /* MMT_SAFE_MATH_H */
