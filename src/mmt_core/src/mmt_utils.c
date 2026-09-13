#include <math.h>
#include "mmt_utils.h"
// #include "../public_include/mmt_utils.h"

int hex2int(char hc){
    int ret = hc;
    if(ret < 0) ret += 256;
    return ret;
}

/* Bounded, NUL-free substring search over byte spans — the primitive the
 * str_*_n family shares. Finds needle[0..needle_len) inside
 * haystack[0..haystack_len) without relying on a NUL terminator on either
 * side. Returns a pointer into haystack, or NULL when absent. */
static const char * mmt_memmem(const char *haystack, size_t haystack_len,
                               const char *needle, size_t needle_len){
    if(needle_len == 0) return haystack;
    if(haystack_len < needle_len) return NULL;

    const char *last = haystack + haystack_len - needle_len;
    const char *p = haystack;
    while(p <= last){
        p = (const char *)memchr(p, needle[0], (size_t)(last - p) + 1);
        if(p == NULL) return NULL;
        if(memcmp(p, needle, needle_len) == 0) return p;
        p++;
    }
    return NULL;
}

char * str_hex2str(char *hstr, int start_index, int end_index){

    if(hstr == NULL) return NULL;

    if(start_index < 0) return NULL;

    if(end_index < start_index ) return NULL;

    /* end_index must be inside the string */
    size_t hlen = strlen(hstr);
    if((size_t)end_index >= hlen) return NULL;

    /* [start_index, end_index] is inclusive on both ends: examine
     * end-start+1 characters and keep room for the terminating NUL.
     * Callers pass length-1 as end_index for an NUL-terminated input,
     * so the last examined character is the final byte before NUL. */
    int length = end_index - start_index + 1;

    char *ret;
    ret = (char*)malloc(length + 1);
    if(ret == NULL) return NULL;
    int i = 0;
    
    int current_index = 0;

    while(i < length){
        int c = hstr[start_index + i];
        if(c > 19 && c < 127){
            ret[current_index] = hstr[start_index + i];
            current_index++;
        }
        i++;
    }
    ret[current_index]='\0';

    if(current_index == 0){
        free(ret);
        char *empty = (char*)malloc(1);
        if(empty == NULL) return NULL;
        empty[0] = '\0';
        return empty;
    }
    char *str_str = str_sub_n(ret, (size_t)current_index, 0, current_index - 1);
    free(ret);
    return str_str;
}

int str_hex2int(char *hstr, int start_index, int end_index){

    if(hstr == NULL) return -1;

    if(start_index < 0) return -1;

    if(end_index < start_index ) return -1;

    int length = end_index - start_index + 1;
    int i = length;
    int ret = 0;

    while(i >= 1){
        ret += hex2int(hstr[start_index + length - i])*pow(16,2*(i-1));
        i--;
    }

    return ret;
}

int str_hex2int_n(char *hstr, size_t hstr_len, int start_index, int end_index){

    if(hstr == NULL) return -1;

    if(start_index < 0) return -1;

    if(end_index < start_index ) return -1;

    /* end_index must stay inside the supplied buffer. The bound is hstr_len,
     * never strlen(hstr), so non-NUL-terminated input is safe (F-BUG-023). */
    if((size_t)end_index >= hstr_len) return -1;

    int length = end_index - start_index + 1;
    int i = length;
    int ret = 0;

    while(i >= 1){
        ret += hex2int(hstr[start_index + length - i])*pow(16,2*(i-1));
        i--;
    }

    return ret;
}

unsigned long hex2dec(char *str){
    
    int i;
    for(i = 0; i < strlen(str); i++ ){
        int nb = str[i];
        if (!( (nb >=48 && nb <= 57) || (nb >= 97 && nb<=102) || (nb >= 65 && nb<=70) )){
            return -1;
        }
    }

    unsigned long ul;
    ul = strtoul (str, NULL, 16);
    if(ul == 0){
        int i;
        for(i = 0; i < strlen(str); i++){
            if(str[i] != '0') return -1;
        }
    }
    return ul;
}


int char2int(char x){
    int nb = x ;
    if(nb >=48 && nb <= 57) return (nb-48);
    if(nb >= 65 && nb<=70) return ((nb-65) + 10);
    if(nb >= 97 && nb<=102) return ((nb-97) + 10);
    return -1;
}


char hex2char(char a, char b){
    int na = char2int(a);
    int nb = char2int(b);
    if(na == -1 || nb == -1) return '\0';
    char c = na * 16 + nb;
    return c;
}

char * hex2str(char *h_str){

    if(h_str==NULL) return NULL;

    int str_len = strlen(h_str);
    if ((str_len % 2)!=0) return NULL;
    char *ret;
    ret = (char*)malloc(str_len/2 + 1);
    if(ret == NULL) return NULL;
    int i = 0 ;
    int j = 0;
    for(i = 0; i < str_len/2; i++){
        char c = hex2char(h_str[2*i],h_str[2*i+1]);
        int nb_c = c;
        if(nb_c >32 && nb_c < 127){
            ret[j] = c;
            j++;
            // debug("%s\n",ret);
        }else{
            // debug("ooop\n");
        }
    }
    ret[j]='\0';
    return ret;
}

int str_compare(char * str1, char * str2){

    if(str1 == NULL && str2 == NULL) return 1;

    if(str1!=NULL && str2!=NULL){
        return strcmp(str1,str2)==0;
    }
    return 0;
 }

 int str_index(char * str, char *  substr){

    if(str!=NULL && substr!=NULL){
        char *p_index;
        p_index = strstr(str,substr);
        if(p_index == NULL) return -1;
        return (strlen(str)-strlen(p_index));
    }
    return -1;
 }
    
 char * str_sub(char * str, int start_index, int end_index){
    if(str == NULL) return NULL;

    if(start_index < 0) return NULL;

    if(end_index < 0) return NULL;

    if((size_t)end_index >= strlen(str)) return NULL;

    if( start_index > end_index) return NULL;

    int len = end_index - start_index + 1;
    char * sub;
    sub = (char *)malloc(len + 1);
    if(sub == NULL) return NULL;
    memcpy(sub,(str + start_index), len);
    sub[len]='\0';
    return sub;
 }

 /* Length-bounded variant of str_sub(): the only bound is the supplied
  * str_len, so str does not need to be NUL-terminated (F-BUG-023). */
 char * str_sub_n(char * str, size_t str_len, int start_index, int end_index){
    if(str == NULL) return NULL;

    if(start_index < 0) return NULL;

    if(end_index < 0) return NULL;

    if((size_t)end_index >= str_len) return NULL;

    if( start_index > end_index) return NULL;

    int len = end_index - start_index + 1;
    char * sub;
    sub = (char *)malloc(len + 1);
    if(sub == NULL) return NULL;
    memcpy(sub,(str + start_index), len);
    sub[len]='\0';
    return sub;
 }

 char * str_combine(char * str1, char * str2){
    char * comb;
    int len = 0;
    if(str2 == NULL && str1 == NULL) return NULL;

    if(str1 == NULL && str2 != NULL) {
        len = strlen(str2);
        comb = (char *)malloc(len + 1);
        if(comb == NULL) return NULL;
        memcpy(comb,str2,len);
        comb[len]='\0';
    }else if(str2 == NULL && str1 != NULL){
        len = strlen(str1);
        comb = (char *)malloc(len + 1);
        if (comb == NULL)
            return NULL;
        strcpy(comb,str1);
    }else {
        len = strlen(str1) + strlen(str2);
        comb = (char*)malloc(len + 1);
        if (comb == NULL)
            return NULL;
        strcpy(comb,str1);
        strcat(comb,str2);
    }
    return comb;
 }

// char ** str_split(char * str, char * spliter){
//     char **array_string;
//     if(str != NULL && spliter !=NULL){
//         char *str_input = str;
//         char * array_string[strlen(str_input)];
//         int start_index = 0;
//         int s_index;
//         s_index = str_index(str_input,spliter);
//         int index_of_string = 0;
//         while(s_index != -1){
//             if(s_index == 0){
//                 start_index = start_index + strlen(spliter);
//             }else{
//                 char *new_string;
//                 new_string = str_sub(str_input,start_index,start_index + s_index-1);
//                 array_string[index_of_string] = new_string;
//                 start_index = start_index + s_index + strlen(spliter);
//                 index_of_string++; 
//                 // free(new_string);
//             }
//             s_index = str_index(str_input + start_index,spliter);   
//         }
//         if(str_input + start_index != NULL){
//             char *last_string;
//             last_string = str_sub(str_input, start_index, strlen(str_input)-1);
//             array_string[index_of_string] = last_string;
//             // free(last_string);
//         }
//         array_string[index_of_string+1]=NULL;
//         return array_string;
//      }
//     return NULL;
    
//  }

int * str_get_indexes(char *str, char* str1){
    if(str ==  NULL || str1 == NULL) return NULL;

    if(str1[0] == '\0') return NULL;

    size_t sep_len = strlen(str1);
    if(sep_len == 0) return NULL;

    int str1_index = str_index(str,str1);
    if(str1_index == -1) return NULL;

    int *indexes;
    indexes = (int*)malloc((strlen(str)+1)*sizeof(int));
    if(indexes == NULL) return NULL;
    int start_index = 0;
    int current_index = 0;
    while(str1_index != -1){
        indexes[current_index] = start_index + str1_index;
        start_index = start_index + str1_index + strlen(str1);
        str1_index = str_index(str + start_index,str1);
        current_index++;
    }

    indexes[current_index]=-1;

    int *res;
    res = (int*)malloc((current_index + 1)*sizeof(int));
    if(res == NULL) {
        free(indexes);
        return NULL;
    }
    int i = 0;
    for(i = 0;i <current_index + 1;i++){
        res[i]=indexes[i];
    }
    free(indexes);
    return res;
}

/* Length-bounded variant of str_get_indexes(): the scan never reads past
 * str_len and the needle is matched over exactly str1_len bytes, so neither
 * side needs a NUL terminator (F-BUG-023). */
int * str_get_indexes_n(char *str, size_t str_len, char *str1, size_t str1_len){
    if(str == NULL || str1 == NULL) return NULL;

    if(str1_len == 0) return NULL;

    /* A needle longer than the bounded haystack can never match — this also
     * refuses a needle that would reach beyond the supplied buffer. */
    if(str1_len > str_len) return NULL;

    /* Indexes are reported as int, like str_get_indexes(); a haystack that
     * cannot be indexed by int is refused instead of truncated. */
    if(str_len > (size_t)INT32_MAX) return NULL;

    int *indexes;
    indexes = (int*)malloc((str_len + 1)*sizeof(int));
    if(indexes == NULL) return NULL;

    size_t start = 0;
    int current_index = 0;
    while(str_len - start >= str1_len){
        const char *found = mmt_memmem(str + start, str_len - start, str1, str1_len);
        if(found == NULL) break;
        size_t hit = (size_t)(found - str);
        indexes[current_index] = (int)hit;
        start = hit + str1_len;
        current_index++;
    }

    if(current_index == 0){
        free(indexes);
        return NULL;
    }

    indexes[current_index] = -1;

    int *res;
    res = (int*)malloc((current_index + 1)*sizeof(int));
    if(res == NULL) {
        free(indexes);
        return NULL;
    }
    memcpy(res, indexes, (current_index + 1)*sizeof(int));
    free(indexes);
    return res;
}


 char * str_replace(char * str, char * str1, char * rep){

    if(str == NULL) return NULL;

    if(str1 == NULL || rep == NULL) {
        return str_copy(str);
    }

    int * array_index = str_get_indexes_n(str,strlen(str),str1,strlen(str1));

    if(array_index == NULL) {
        return str_copy(str);
    }
    int current_index = 0;

    int nb_element =0;
    while(array_index[nb_element] != -1){
        nb_element++;
    }

    int new_string_len = strlen(str) + nb_element * strlen(rep) - nb_element * strlen(str1)+1;
    char * new_string;
    new_string = (char * )malloc(new_string_len);
    if(new_string == NULL) {
        free(array_index);
        return NULL;
    }
    new_string[0] = '\0';

    if(array_index[current_index] != 0){
        char * str_substr = str_sub_n(str,strlen(str),0,array_index[current_index]-1);
        strcpy(new_string,str_substr);
        free(str_substr);
    }

    while(array_index[current_index + 1] != -1){

        char * str_substr = str_sub_n(str,strlen(str),array_index[current_index] + strlen(str1),array_index[current_index + 1] -1);
        
        if(strlen(new_string)==0){
            strcpy(new_string,rep);
        }else{
            strcat(new_string,rep);
        }
        strcat(new_string,str_substr);
        free(str_substr);
        current_index ++;
    }

    // The spliter is at the end of string
    if(strlen(str) >= array_index[current_index] + strlen(str1)){
        char * str_substr = str_sub_n(str,strlen(str),array_index[current_index] + strlen(str1),strlen(str) -1);
        strcat(new_string,rep);    
        if(str_substr != NULL){
            strcat(new_string,str_substr);
            free(str_substr);
        }
    }

    new_string[new_string_len-1] = '\0';

    free(array_index);
    
    return new_string;

 }

 char * str_subvalue(char *str, char* begin, char * end){
    if(str == NULL) return NULL;
    
    if(begin == NULL && end == NULL) return NULL;

    int begin_index = str_index(str,begin);
    int end_index = str_index(str,end);

    if(begin == NULL){
        return str_sub_n(str,strlen(str),0,end_index - 1);
    }

    if(end == NULL){
        return str_sub_n(str,strlen(str),begin_index + strlen(begin),strlen(str)-1);
    }
    

    if(begin_index == -1 ) return NULL;

    
    if(end_index == -1) return NULL;

    if(begin_index + strlen(begin) >= end_index) return NULL;

    int start_index = begin_index + strlen(begin);

    return str_sub_n(str,strlen(str),start_index,end_index - 1);
}

char * str_copy(char *str2){
    
    char *str1 = NULL;
    
    if(str2 != NULL){
        int length = strlen(str2);

        str1 = malloc(length + 1);
        if(str1 == NULL) return NULL;
        memcpy(str1,str2,length);

        str1[length] = '\0';
    }
    
    return str1;
}

void str_print_array(char **array){
    int i=0;
    while(array[i] != NULL){
        printf("Array[%d]: %s\n",i,array[i]);
        i++;
    }
}
