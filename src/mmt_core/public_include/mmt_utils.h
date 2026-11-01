/**
 * @file
 * Utility helpers exported by libmmt_core: hexadecimal conversions and
 * string search, copy, split and replace helpers.
 *
 * Author: montimage
 *
 * Created on 11 Novembre 2015, 21h00 by Luong Nguyen
 */

#ifndef MMT_UTILS_H
#define MMT_UTILS_H

#ifdef  __cplusplus
extern "C" {
#endif

 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdint.h>
 #include <math.h>
 #include <stdbool.h>
 #include <limits.h> /* ULONG_MAX: MMT_HEX2DEC_ERROR */
 #include "mmt_exports.h"

/**
 * Convert a hexa character to an integer number
 * @param  hc hexa character
 * @return    the value from 0->255;
 */
MMTAPI int MMTCALL hex2int(char hc);

/**
 * Convert a hexa string to an integer number
 * @param  hstr   hexa string
 * @param  start_index index to start calculation
 * @param  end_index index to finish calculation
 * @return        -1 if:
 *                   @p hstr is NULL
 *                   @p start_index <0
 *                   @p end_index <  start_index
 * @deprecated Use str_hex2int_n() — it takes the buffer length explicitly and
 *             never reads past it, so it is safe on non-NUL-terminated input.
 */
MMTAPI int MMTCALL str_hex2int(char *hstr, int start_index, int end_index)
    __attribute__((deprecated("use str_hex2int_n; removal in 2.0.0")));

/**
 * Length-bounded variant of str_hex2int()
 * @param  hstr        hexa buffer — does not need to be NUL-terminated
 * @param  hstr_len    number of valid bytes at @p hstr
 * @param  start_index index to start calculation
 * @param  end_index   index to finish calculation (inclusive)
 * @return        -1 if:
 *                   @p hstr is NULL
 *                   @p start_index < 0
 *                   @p end_index < @p start_index
 *                   @p end_index >= @p hstr_len
 */
MMTAPI int MMTCALL str_hex2int_n(char *hstr, size_t hstr_len, int start_index, int end_index);

/**
 * Get printable value of a hexa string
 * @param  hstr        hexa string
 * @param  start_index start index
 * @param  end_index   end index
 * @return          NULL if:
 *                   @p hstr is NULL
 *                   @p start_index <0
 *                   @p end_index <  start_index
 */
MMTAPI char * MMTCALL str_hex2str(char *hstr, int start_index, int end_index);

/**
 * @fn unsigned long hex2dec(char* str)
 * Convert a string of a hexa number to decimal number
 * @param  str string
 * @return     MMT_HEX2DEC_ERROR if the string is not a hexa number
 *              0 if all the characters of @p str is '0'
 *             value of hexa number in decimal system
 * @deprecated No known caller (issue #541); removal in 2.0.0.
 */
#define MMT_HEX2DEC_ERROR ULONG_MAX /**< issue #546: the value `return -1` used to produce */
MMTAPI unsigned long MMTCALL hex2dec(char* str) __attribute__((deprecated("no known caller (issue #541); removal in 2.0.0")));


/**
 * Convert a hexa character to a number in decimal
 * @param  x character
 * @return   '0'->'9' -> value 0->9
 *           'a'->'f' -> value 10->15        
 *           'A'->'F' -> value 10->15        
 *           -1 otherwise
 */
MMTAPI int MMTCALL char2int(char x);

/**
 * Convert a hex number to a character in ascii table
 * @param  a first character
 * @param  b second character
 * @return    '\0' if a is not hexa character
 *            '\0' if b is not hexa character
 *             character which has value: a *16 + b
 */
MMTAPI char MMTCALL hex2char(char a, char b);


/**
 * Convert a string of a hexa number to a ascii string
 * @param  h_str  hexa string
 * @return        	NULL if @p h_str is NULL
 * 					NULL if there is an '\0' return
 *                	NULL if length of h_str is a number of: 2*n + 1
 *                 a string in ascii table
 * @deprecated No known caller (issue #541); removal in 2.0.0.
 */
MMTAPI char * MMTCALL hex2str(char *h_str) __attribute__((deprecated("no known caller (issue #541); removal in 2.0.0")));


 #define C_EASY_STR_MAX_ARRAY_SIZE 255 ///< Reserved; not read by the SDK.
/**
 * Compare 2 strings
 * @param  str1 String 1
 * @param  str2 The second string
 * @return      0 if:
 *                  @p str1 is NULL and @p str2 is not NULL
 *                  @p str1 is not NULL and @p str2 is NULL
 *                  @p str1 does not equal @p str2
 *              1 if:
 *                  @p str1 and @p str2 are NULL
 *                  @p str1 equals @p str2
 */
 MMTAPI bool MMTCALL str_compare(char * str1, char * str2); // Passed

 /**
  * Get the first index of a substring in a string
  * @param  str    big string
  * @param  substr substring to find the index
  * @return        -1: if @p substr is not a substring of string @p str
  *                    if @p str1 is NULL
  *                    if @p str2 is NULL
  *               >=0: index of @p substr in @p str
  *               
  */
 MMTAPI int MMTCALL str_index(char * str, char *  substr); // Passed

 /**
  * Get a substring of a string with the input of start and end index
  * @param  str         String to get substring from
  * @param  start_index The starting index to get string (>=0)
  * @param  end_index   The ending index of string (< length of @p str)
  * @return             NULL: if @p str is NULL
  *                           if @p start_index <0
  *                           if @p end_index >= length of @p str
  *                           if @p start_index >= @p end_index
  *                     a new string which is the substring of @p str from @p start_index to @p end_index (counts both 2 characters at index @p start_index and @p end_index)
  * @deprecated Use str_sub_n() — it takes the buffer length explicitly and
  *             never reads past it, so it is safe on non-NUL-terminated input.
  */		
 MMTAPI char * MMTCALL str_sub(char * str, int start_index, int end_index) // Passed
    __attribute__((deprecated("use str_sub_n; removal in 2.0.0")));

 /**
  * Length-bounded variant of str_sub()
  * @param  str         buffer to get substring from — does not need to be NUL-terminated
  * @param  str_len     number of valid bytes at @p str
  * @param  start_index The starting index to get string (>=0)
  * @param  end_index   The ending index of string (< @p str_len)
  * @return             NULL: if @p str is NULL
  *                           if @p start_index <0
  *                           if @p end_index <0 or >= @p str_len
  *                           if @p start_index > @p end_index
  *                     a new string which is the substring of @p str from @p start_index to @p end_index (counts both 2 characters at index @p start_index and @p end_index)
  */
 MMTAPI char * MMTCALL str_sub_n(char * str, size_t str_len, int start_index, int end_index);

/**
 * Get the combination of two strings
 * @param  str1 The first string to combine
 * @param  str2 The second string to combine
 * @return      a new string which is a combination of @p str1 and @p str2
 *              NULL if both @p str1 and @p str2 are NULL
 *              A copy of @p str1 if @p str2 is NULL
 *              A copy of @p str2 if @p str1 is NULL
 */
 MMTAPI char * MMTCALL str_combine(char * str1, char * str2); // Passed

/*
 * Split a string by a spliter
 * @param  str     String is going to be split
 * @param  spliter spliter
 * @return         An array of string
 *                 NULL if @p str or @p spliter is(are) NULL
 *                 Array with only 1 element if @p spliter does not exists in @p str
 *                 Array with only 1 element if @p spliter is at the beginning or the end of string
 */
 // char ** str_split(char * str, char * spliter); // Passed
 
 /**
 * Get all indexes of a string in a string
 * @param  str string
 * @param  str1   substring of @p str
 * @return     NULL if:
 *                  @p str is NULL
 *                  @p str1 is NULL
 *                  @p str1 does not belong to @p str
 *             an array of indexes of @p str1 in @p str
 * @deprecated Use str_get_indexes_n() — it bounds the scan by an explicit
 *             buffer length and never reads past it, so it is safe on
 *             non-NUL-terminated input.
 */
MMTAPI int * MMTCALL str_get_indexes(char *str, char *str1) // Passed
    __attribute__((deprecated("use str_get_indexes_n; removal in 2.0.0")));

/**
 * Length-bounded variant of str_get_indexes()
 * @param  str      haystack buffer — does not need to be NUL-terminated
 * @param  str_len  number of valid bytes at @p str
 * @param  str1     needle buffer — does not need to be NUL-terminated
 * @param  str1_len number of valid bytes at @p str1
 * @return     NULL if:
 *                  @p str or @p str1 is NULL
 *                  @p str1_len is 0 or > @p str_len
 *                  @p str1 does not occur in the first @p str_len bytes of @p str
 *             an array of indexes of @p str1 in @p str, terminated by -1
 */
MMTAPI int * MMTCALL str_get_indexes_n(char *str, size_t str_len, char *str1, size_t str1_len);

/**
 * Replace a substring by another substring in a string
 * @param  str      big string
 * @param  str1     substring is going to be replaced
 * @param  rep replacing string
 * @return          NULL if:
 *                       @p str is NULL
 *                  @p str if :
 *                       @p str1 is NULL
 *                       @p str1 does not belong to @p str
 *                       @p rep is NULL
 *                  new value of @p str with all the @p str1 are replaced by @p rep
 */
 MMTAPI char * MMTCALL str_replace(char * str, char * str1, char * rep); // Passed


/**
* Get a substring between 2 substrings
* @param  str     big string
* @param  begin   substring begin of value (the first appears in @p str)
* @param  end     substring end of value (the first appears in @p str)
* @return         substring between 2 substring
*                 if @p end is NULL then return substring from @p begin to the end of string
*                 if @p begin is NULL then return substring from beginning to the string @p end
*                 return NULL if: 
*                   @p str  is NULL
*                   @p begin is not a substring of @p str
*                   @p end is not a substring of @p str
*                   @p begin and @p end are NULL
*                   @p begin and @p end are overlap or next each other in @p str
*                   @p begin is after @p end in @p str
*/
MMTAPI char * MMTCALL str_subvalue(char *str, char* begin, char * end); // Passed

/**
 * Copy a string
 * @param str2 string to be coppied
 * @return new string
 */
MMTAPI char * MMTCALL str_copy(char *str2);

/**
 * Print string in an array of string until the first NULL element;
 * @param array array string
 * @deprecated No known caller (issue #541); removal in 2.0.0.
 */
MMTAPI void MMTCALL str_print_array(char **array) __attribute__((deprecated("no known caller (issue #541); removal in 2.0.0"))); // Passed

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_NDN_H */
