#include <stdio.h>
#include <ctype.h>
#include "rfc2822utils.h"
#include "../mmt_common_internal_include.h"

/**
 * Returns the offset of the first white space character given a printable text string.
 * It should be used only on strings we know are safe for this.
 * @param str the string we are searching in
 * @return the offset of the first occurence of a white space
 */
int get_next_white_space_offset_no_limit(const char * str) {
    int offset = 0;
    while (isgraph(*str)) {
        offset++;
        str++;
    }

    return offset;
}

/**
 * Returns the offset of the first non white space character given a printable text string.
 * It should be used only on strings we know are safe for this.
 * @param str the string we are searching in
 * @return the offset of the first occurence of a non white space
 */
int get_next_non_white_space_offset_no_limit(const char * str) {
    int offset = 0;
    while (isspace(*str)) {
        offset++;
        str++;
    }

    return offset;
}

/**
 * Returns the first occurance of char_to_find in str string within a maximum length of max.
 * It should be used only with strings we know are more than max length.
 * @param str the string we are searching in
 * @param char_to_find the char to find
 * @param max the maximum number of octets to inspect
 * @return a pointer to the first occurence of char_to_find in str, null if nothing was found in the first max octets of str
 */
const char * mmt_find_char_instance(const char * str, char char_to_find, int max) {
    const char *temp_str = str;
    while ((*temp_str != char_to_find) && max) {
        max--;
        temp_str++;
    }

    // Know we check if we found the char
    if (*temp_str == char_to_find)
        return temp_str;
    else
        return NULL; // this means we reached max, NULL should be returned
}

/**
 * Checks if the given character is space or horizental tab
 * @param c the character to check
 * @return A value different from zero (i.e., true) if indeed c is a space or horizental tab character. Zero (i.e., false) otherwise.
 */
int is_space_or_htab(char c) {
    if(c == ' ' || c == '\t') return 1;
    return 0;
}

/**
 * Prints max characters from the given string.
 * @param str the string to print out.
 * @param max maximum number of characters to print.
 */
void print_char_per_char(const char * str, int max) {
    while (max) {
        printf("%c", *str);
        max--;
        str++;
    }
}

/**
 * Ignore any CRLF at the beginning of the message. Returns the number of ignored octets
 * """RFC 2616 - Section 4.1 - page 21: In the interest of robustness,
 * servers SHOULD ignore any empty line(s) received where a Request-Line is
 * expected. In other words, if the server is reading the protocol stream at
 * the beginning of a message and receives a CRLF first, it should
 * ignore the CRLF.Parse a single line of the HTTP header."""
 * @param msg: the message
 * @param msg_len: the message length
 * @return the offset defined by double the number of CRLF at the beginning of the message
 */
int ignore_starting_crlf(const char * msg, int msg_len) {
    int offset = 0;
    while (msg_len >= 2) {
        if (msg[offset] == '\r' && msg[offset + 1] == '\n') {
            msg_len -= 2;
            offset += 2;
        } else {
            break; //Leave the while loop
        }
    }
    return offset;
}

/**
 * Parse a single line of the header (HTTP, RTSP, ...).  returns the length of the line.
 * If the line is truncated, return -1 and put code to Truncated.
 */
int get_next_header_line_length(const char * msg, int msg_len, int * code) {
    int header_len;
    char nb_termination = 1;

    if (msg_len == 0) {
        //TODO: code should be updated here
        return 0;
    }

    header_len = 0;

    //Find the end of the header line
    while ((header_len < msg_len - 1)) {
        if (msg[header_len] == LF && (msg[header_len + 1] != SP && msg[header_len + 1] != HT)) {
            /* Taking into account folded header lines! Refer to RFC 2616 section 19 and RFC 2822 section 2.2.3
             * Is is possible to have a header split into multiple lines.
             * Remember a LWS is defined to be: [CRLF] 1*( SP | HT ) (RFC 2616 section 2.2)
             */
            break;
        }
        header_len++;
    }

    //If if we exited the while loop because of reaching the end of the message
    if (header_len == (msg_len - 1) && (msg[header_len + 1] != LF)) {
        //We reached the end of the message and there is no new line characters, the message is truncated
        *code = TRUNCATED;
        return 0;
    }

    /* found, check if we have proper CRLF */
    if (msg[header_len] == LF && msg[header_len - 1] == CR) {
        nb_termination = 2; /* Normally, we should get here every time there is a non truncated header.
                             */
    }

    header_len++; // To get the real length of the header

    *code = nb_termination;
    return header_len;
}

/**
 * Returns the offset of the value part.
 *
 */
int get_value_offset(const char * msg, int line_len) {
    const char * colon;

    /* line should be normal header line, find colon */
    colon = mmt_find_char_instance(msg, ':', line_len);
    if (colon == NULL) {
        /* error in header line, report it */
        return -1; //TODO replace with definition. Header line badly formatted, no column was found
    }

    colon++;
    while (is_space_or_htab(*colon)) {
        colon++;
    }
    return (colon - msg);
}

int get_field_len(const char * str, int line_len) {
    const char * colon;

    /* line should be normal header line, find colon */
    colon = mmt_find_char_instance(str, ':', line_len);
    if (colon == NULL) {
        /* error in header line, report it */
        return -1; //TODO replace with definition. Header line badly formatted, no column was found
    }

    //colon--;
    while (isspace(*colon)) {
        colon--;
    }
    return (colon - str);
}
