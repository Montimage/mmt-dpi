/* 
 * File:   mmt_utils.h
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
 #include "math.h"
/**
 * Convert a hexa character to an integer number
 * @param  hc hexa character
 * @return    the value from 0->255;
 */
int hex2int(char hc);

/**
 * Convert a hexa string to an integer number
 * @param  hstr   hexa string
 * @param  start_index index to start calculation
 * @param  end_index index to finish calculation
 * @return        -1 if:
 *                   @hstr is NULL
 *                   @start_index <0
 *                   @end_index <  start_index
 */
int str_hex2int(char *hstr, int start_index, int end_index);

/**
 * Get printable value of a hexa string
 * @param  hstr        hexa string
 * @param  start_index start index
 * @param  end_index   end index
 * @return          NULL if:
 *                   @hstr is NULL
 *                   @start_index <0
 *                   @end_index <  start_index      
 */
char *str_hex2str(char *hstr, int start_index, int end_index);

/**
 * Convert a string of a hexa number to decimal number
 * @param  str string
 * @return     -1 if the string is not a hexa number
 *              0 if all the characters of @str is '0'
 *             value of hexa number in decimal system
 */
unsigned long hex2dec(char* str);


/**
 * Convert a hexa character to a number in decimal
 * @param  x character
 * @return   '0'->'9' -> value 0->9
 *           'a'->'f' -> value 10->15        
 *           'A'->'F' -> value 10->15        
 *           -1 otherwise
 */
int char2int(char x);

/**
 * Convert a hex number to a character in ascii table
 * @param  a first character
 * @param  b second character
 * @return    '\0' if a is not hexa character
 *            '\0' if b is not hexa character
 *             character which has value: a *16 + b
 */
char hex2char(char a, char b);


/**
 * Convert a string of a hexa number to a ascii string
 * @param  h_str  hexa string
 * @param  length length of string
 * @return        	NULL if @h_str is NULL
 * 					NULL if there is an '\0' return
 *                	NULL if length of h_str is a number of: 2*n + 1
 *                 a string in ascii table
 */
char * hex2str(char *h_str);


 #define C_EASY_STR_MAX_ARRAY_SIZE 255
/**
 * Compare 2 strings
 * @param  str1 String 1
 * @param  str2 The second string
 * @return      0 if:
 *                  @str1 is NULL and @str2 is not NULL
 *                  @str1 is not NULL and @str2 is NULL
 *                  @str1 does not equal @str2
 *              1 if:
 *                  @str1 and @str2 are NULL
 *                  @str1 equals @str2
 */
 int str_compare(char * str1, char * str2); // Passed

 /**
  * Get the first index of a substring in a string
  * @param  str    big string
  * @param  substr substring to find the index
  * @return        -1: if @substr is not a substring of string @str
  *                    if @str1 is NULL
  *                    if @str2 is NULL
  *               >=0: index of @substr in @str
  *               
  */
 int str_index(char * str, char *  substr); // Passed

 /**
  * Get a substring of a string with the input of start and end index
  * @param  str         String to get substring from
  * @param  start_index The starting index to get string (>=0)
  * @param  end_index   The ending index of string (< length of @str)
  * @return             NULL: if @str is NULL
  *                           if @start_index <0
  *                           if @end_index >= length of @str
  *                           if @start_index >= @end_index
  *                     a new string which is the substring of @str from @start_index to @end_index (counts both 2 characters at index @start_index and @end_index)
  */		
 char * str_sub(char * str, int start_index, int end_index); // Passed

/**
 * Get the combination of two strings
 * @param  str1 The first string to combine
 * @param  str2 The second string to combine
 * @return      a new string which is a combination of @str1 and @str2
 *              NULL if both @str1 and @str2 are NULL
 *              A copy of @str1 if @str2 is NULL
 *              A copy of @str2 if @str1 is NULL
 */
 char * str_combine(char * str1, char * str2); // Passed

/**
 * Split a string by a spliter
 * @param  str     String is going to be split
 * @param  spliter spliter
 * @return         An array of string
 *                 NULL if @str or @spliter is(are) NULL
 *                 Array with only 1 element if @spliter does not exists in @str
 *                 Array with only 1 element if @spliter is at the beginning or the end of string
 */
 char ** str_split(char * str, char * spliter); // Passed
 
 /**
 * Get all indexes of a string in a string
 * @param  str string
 * @param  str1   substring of @str
 * @return     NULL if:
 *                  @str is NULL
 *                  @str1 is NULL
 *                  @str1 does not belong to @str
 *             an array of indexes of @str1 in @str
 */
int * str_get_indexes(char *str, char *str1); // Passed

/**
 * Replace a substring by another substring in a string
 * @param  str      big string
 * @param  str1     substring is going to be replaced
 * @param  rep replacing string
 * @return          NULL if:
 *                       @str is NULL
 *                  @str if :
 *                       @str1 is NULL
 *                       @str1 does not belong to @str
 *                       @rep is NULL
 *                  new value of @str with all the @str1 are replaced by @rep
 */
 char * str_replace(char * str, char * str1, char * rep); // Passed


/**
* Get a substring between 2 substrings
* @param  str     big string
* @param  begin   substring begin of value (the first appears in @str)
* @param  end     substring end of value (the first appears in @str)
* @return         substring between 2 substring
*                 if @end is NULL then return substring from @begin to the end of string
*                 if @begin is NULL then return substring from beginning to the string @end
*                 return NULL if: 
*                   @str  is NULL
*                   @begin is not a substring of @str
*                   @end is not a substring of @str
*                   @begin and @end are NULL
*                   @begin and @end are overlap or next each other in @str
*                   @begin is after @end in @str
*/
char * str_subvalue(char *str, char* begin, char * end); // Passed

/**
 * Add a string into an array of string. New string will be filled in the first NULL element of array
 * @param  array Array of string
 * @param  str   String to add
 * @return       if @str is NULL return array
 *               if @array is NULL return new array with @str is the first element
 *               new array with the @str is added to the first NULL element in array (not at the end of array)
 */
char ** str_add_string_to_array(char **array,char *str); // Passed


/**
 * Copy a string
 * @param str2 string to be coppied
 * @return new string
 */
char* str_copy(char *str2);

/**
 * Print string in an array of string until the first NULL element;
 * @param array array string
 */
void str_print_array(char **array); // Passed

/**
 * Executes a command in linux and return the output
 * @param  cmd command to be executed
 * @return     the output of command
 */
char * cmd_run_command(char *cmd); // Passed

#ifdef  __cplusplus
}
#endif

#endif  /* MMT_NDN_H */