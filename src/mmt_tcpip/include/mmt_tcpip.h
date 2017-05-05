/*
 * File:   mmt_tcpip_utils.h
 * Author: montimage
 *
 * Created on 28 mai 2015, 17:21
 */

#ifndef MMT_TCPIP_H
#define MMT_TCPIP_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>
#include "mmt_tcpip_protocols.h"
#include "mmt_tcpip_attributes.h"

static inline int get_content_class_by_content_type(char * str) {
    int str_len = strlen(str);

    if (str_len > 12 && memcmp(str, "application/", 12) == 0) {
        // For non-standard files : x prefix
        // For vendor-specific files : vnd prefix
        if (str_len >= 15 && memcmp(&str[12], "flv", 3) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 17 && memcmp(&str[12], "x-fcs", 5) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 20 && memcmp(&str[12], "atom+xml", 8) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 22 && memcmp(&str[12], "ecmascript", 10) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 22 && memcmp(&str[12], "javascript", 10) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 16 && memcmp(&str[12], "json", 4) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 15 && memcmp(&str[12], "ogg", 3) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 19 && memcmp(&str[12], "rdf+xml", 7) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 19 && memcmp(&str[12], "rss+xml", 7) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 20 && memcmp(&str[12], "soap+xml", 8) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 21 && memcmp(&str[12], "font-woff", 9) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 23 && memcmp(&str[12], "x-font-woff", 11) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 21 && memcmp(&str[12], "xhtml+xml", 9) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 19 && memcmp(&str[12], "xml-dtd", 7) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 19 && memcmp(&str[12], "xop+xml", 7) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 28 && memcmp(&str[12], "vnd.rn-realmedia", 16) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 22 && memcmp(&str[12], "x-font-ttf", 10) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 24 && memcmp(&str[12], "x-javascript", 12) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 29 && memcmp(&str[12], "x-shockwave-flash", 17) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 33 && memcmp(&str[12], "x-www-form-urlencoded", 21) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        /* Skip the rest as application family */
        /*
        if (str_len >= 19 && memcmp(&str[12], "EDI-X12", 7) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 19 && memcmp(&str[12], "EDIFACT", 7) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 24 && memcmp(&str[12], "octet-stream", 12) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 15 && memcmp(&str[12], "pdf", 3) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 22 && memcmp(&str[12], "postscript", 10) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 15 && memcmp(&str[12], "zip", 3) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 16 && memcmp(&str[12], "gzip", 4) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 23 && memcmp(&str[12], "vnd.ms.wms-", 11) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 39 && memcmp(&str[12], "vnd.oasis.opendocument.text", 27) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 46 && memcmp(&str[12], "vnd.oasis.opendocument.spreadsheet", 36) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 47 && memcmp(&str[12], "vnd.oasis.opendocument.presentation", 35) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 43 && memcmp(&str[12], "vnd.oasis.opendocument.graphics", 31) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 24 && memcmp(&str[12], "vnd.ms-excel", 12) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 65 && memcmp(&str[12], "vnd.openxmlformats-officedocument.spreadsheetml.sheet", 53) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 29 && memcmp(&str[12], "vnd.ms-powerpoint", 17) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 73 && memcmp(str, "vnd.openxmlformats-officedocument.presentationml.presentation", 61) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 71 && memcmp(&str[12], "vnd.openxmlformats-officedocument.wordprocessingml.document", 59) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 31 && memcmp(&str[12], "vnd.mozilla.xul+xml", 19) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 36 && memcmp(&str[12], "vnd.google-earth.kml+xml", 24) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 17 && memcmp(&str[12], "x-dvi", 5) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 19 && memcmp(&str[12], "x-latex", 7) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 21 && memcmp(&str[12], "x-stuffit", 9) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 28 && memcmp(&str[12], "x-rar-compressed", 16) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 17 && memcmp(&str[12], "x-tar", 5) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 17 && memcmp(&str[12], "x-deb", 5) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 21 && memcmp(&str[12], "x-mpegURL", 9) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        // For PKCS standard files: x-pkcs prefix
        if (str_len >= 20 && memcmp(&str[12], "x-pkcs12", 8) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 32 && memcmp(&str[12], "x-pkcs7-certificates", 20) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 31 && memcmp(&str[12], "x-pkcs7-certreqresp", 19) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 24 && memcmp(&str[12], "x-pkcs7-mime", 12) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
        if (str_len >= 29 && memcmp(&str[12], "x-pkcs7-signature", 17) == 0) {
            return MMT_CONTENT_FAMILY_APPLICATION;
        }
         */
        return MMT_CONTENT_FAMILY_APPLICATION;
    }
    if (str_len > 6 && memcmp(str, "audio/", 6) == 0) {
        return MMT_CONTENT_FAMILY_AUDIO;
        /* This is audio do nothing else
        if (str_len >= 11 && memcmp(str, "audio/basic", 11) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 9 && memcmp(str, "audio/L24", 9) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 9 && memcmp(str, "audio/mp4", 9) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 10 && memcmp(str, "audio/mpeg", 10) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 12 && memcmp(str, "audio/x-mpeg", 12) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 11 && memcmp(str, "audio/mpeg3", 11) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 11 && memcmp(str, "audio/mp4a", 10) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 24 && memcmp(str, "audio/x-wav", 11) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 20 && memcmp(str, "audio/x-pn-realaudio", 20) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 9 && memcmp(str, "audio/ogg", 9) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 12 && memcmp(str, "audio/vorbis", 12) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 22 && memcmp(str, "audio/vnd.rn-realaudio", 22) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 14 && memcmp(str, "audio/vnd.wave", 14) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 10 && memcmp(str, "audio/webm", 10) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        // For non-standard files : x prefix
        if (str_len >= 11 && memcmp(str, "audio/x-aac", 11) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
        if (str_len >= 11 && memcmp(str, "audio/x-caf", 11) == 0) {
            return MMT_CONTENT_FAMILY_AUDIO;
        }
         */
    }
    if (str_len > 6 && memcmp(str, "image/", 6) == 0) {
        return MMT_CONTENT_FAMILY_IMAGE;
        /* This is Image, do nothing else
        if (str_len >= 9 && memcmp(str, "image/gif", 9) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        if (str_len >= 10 && memcmp(str, "image/jpeg", 10) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        if (str_len >= 11 && memcmp(str, "image/pjpeg", 11) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        if (str_len >= 9 && memcmp(str, "image/png", 9) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        if (str_len >= 13 && memcmp(str, "image/svg+xml", 13) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        if (str_len >= 10 && memcmp(str, "image/tiff", 10) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        if (str_len >= 24 && memcmp(str, "image/vnd.microsoft.icon", 24) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
        // For non-standard files : x prefix
        if (str_len >= 11 && memcmp(str, "image/x-xcf", 11) == 0) {
            return MMT_CONTENT_FAMILY_IMAGE;
        }
         */
    }

    if (str_len > 8 && memcmp(str, "message/", 8) == 0) {
        return MMT_CONTENT_FAMILY_MESSAGE;
        /* This is message type, do nothing else
        if (str_len >= 12 && memcmp(str, "message/http", 12) == 0) {
            return MMT_CONTENT_FAMILY_MESSAGE;
        }
        if (str_len >= 16 && memcmp(str, "message/imdn+xml", 16) == 0) {
            return MMT_CONTENT_FAMILY_MESSAGE;
        }
        if (str_len >= 15 && memcmp(str, "message/partial", 15) == 0) {
            return MMT_CONTENT_FAMILY_MESSAGE;
        }
        if (str_len >= 14 && memcmp(str, "message/rfc822", 14) == 0) {
            return MMT_CONTENT_FAMILY_MESSAGE;
        }
         */
    }

    if (str_len > 6 && memcmp(str, "model/", 6) == 0) {
        return MMT_CONTENT_FAMILY_MODEL;
        /* This is Model type, return and do nothing else
        if (str_len >= 13 && memcmp(str, "model/example", 13) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
        if (str_len >= 10 && memcmp(str, "model/iges", 10) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
        if (str_len >= 10 && memcmp(str, "model/mesh", 10) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
        if (str_len >= 13 && memcmp(str, "model/vrml", 13) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
        if (str_len >= 16 && memcmp(str, "model/x3d+binary", 16) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
        if (str_len >= 14 && memcmp(str, "model/x3d+vrml", 14) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
        if (str_len >= 13 && memcmp(str, "model/x3d+xml", 13) == 0) {
            return MMT_CONTENT_FAMILY_MODEL;
        }
         * */
    }
    if (str_len > 10 && memcmp(str, "multipart/", 10) == 0) {
        return MMT_CONTENT_FAMILY_MULTIPART;
        /* This is multipart type, do nothing else
        if (str_len >= 15 && memcmp(str, "multipart/mixed", 15) == 0) {
            return MMT_CONTENT_FAMILY_MULTIPART;
        }
        if (str_len >= 21 && memcmp(str, "multipart/alternative", 21) == 0) {
            return MMT_CONTENT_FAMILY_MULTIPART;
        }
        if (str_len >= 17 && memcmp(str, "multipart/related", 17) == 0) {
            return MMT_CONTENT_FAMILY_MULTIPART;
        }
        if (str_len >= 19 && memcmp(str, "multipart/form-data", 19) == 0) {
            return MMT_CONTENT_FAMILY_MULTIPART;
        }
        if (str_len >= 16 && memcmp(str, "multipart/signed", 16) == 0) {
            return MMT_CONTENT_FAMILY_MULTIPART;
        }
        if (str_len >= 19 && memcmp(str, "multipart/encrypted", 19) == 0) {
            return MMT_CONTENT_FAMILY_MULTIPART;
        }
         * */
    }
    if (str_len > 5 && memcmp(str, "text/", 5) == 0) {
        return MMT_CONTENT_FAMILY_TEXT;
        /* This is test, do nothing else
        if (str_len >= 8 && memcmp(str, "text/cmd", 8) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 8 && memcmp(str, "text/css", 8) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 8 && memcmp(str, "text/csv", 8) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 9 && memcmp(str, "text/html", 9) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 15 && memcmp(str, "text/javascript", 15) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 9 && memcmp(str, "text/plain", 9) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 10 && memcmp(str, "text/vcard", 10) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 8 && memcmp(str, "text/xml", 8) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        // For non-standard files : x prefix
        if (str_len >= 14 && memcmp(str, "text/x-gwt-rpc", 14) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
        if (str_len >= 18 && memcmp(str, "text/x-jquery-tmpl", 18) == 0) {
            return MMT_CONTENT_FAMILY_TEXT;
        }
         * */
    }
    if (str_len > 6 && memcmp(str, "video/", 6) == 0) {
        return MMT_CONTENT_FAMILY_VIDEO;
        /* This is video, do nothing else
        if (str_len >= 10 && memcmp(str, "video/mpeg", 10) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 11 && memcmp(str, "video/flash", 11) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 9 && memcmp(str, "video/nsv", 9) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 9 && memcmp(str, "video/mp4", 9) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 11 && memcmp(str, "video/x-m4v", 11) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 9 && memcmp(str, "video/m4v", 9) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 9 && memcmp(str, "video/ogg", 9) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 15 && memcmp(str, "video/quicktime", 15) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 10 && memcmp(str, "video/webm", 10) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 16 && memcmp(str, "video/x-matroska", 16) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 14 && memcmp(str, "video/x-ms-wmv", 14) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 14 && memcmp(str, "video/x-ms-asf", 14) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 24 && memcmp(str, "video/x-msvideo", 15) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 14 && memcmp(str, "video/x-ms-asx", 14) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 9 && memcmp(str, "video/flv", 9) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
        if (str_len >= 11 && memcmp(str, "video/x-flv", 11) == 0) {
            return MMT_CONTENT_FAMILY_VIDEO;
        }
         * */
    }
    return MMT_CONTENT_FAMILY_UNSPECIFIED;
}

static inline char * get_content_class_name_by_content_type(char * str) {
    static char *classes[] = {MMT_CONTENT_LONG_LABELS}; //Safe static as this is read only thing!
    int class_id = get_content_class_by_content_type(str);
    return classes[class_id];
}

static inline int get_content_class_by_content_flags(uint32_t content_flags) {
    if (content_flags & MMT_CONTENT_VIDEO) return MMT_CONTENT_FAMILY_VIDEO;
    if (content_flags & MMT_CONTENT_AUDIO) return MMT_CONTENT_FAMILY_AUDIO;
    if (content_flags & MMT_CONTENT_IMAGE) return MMT_CONTENT_FAMILY_IMAGE;
    return MMT_CONTENT_FAMILY_UNSPECIFIED;
}

static inline char * get_content_class_name_by_content_flags(uint32_t content_flags) {
    static char *classes[] = {MMT_CONTENT_LONG_LABELS}; //Safe static as this is read only thing!
    int class_id = get_content_class_by_content_flags(content_flags);
    return classes[class_id];
}

static inline int get_application_class_by_protocol_id(int id) {
    switch (id) {
        case PROTO_BLOOMBERG:
        case PROTO_MSCDN:
        case PROTO_META:
        case PROTO_163:
        case PROTO_302_FOUND:
        case PROTO_360:
        case PROTO_JD:
        case PROTO_56:
        case PROTO_ADCASH:
        case PROTO_ADDTHIS:
        case PROTO_ALIPAY:
        case PROTO_ALLEGRO:
        case PROTO_AMEBLO:
        case PROTO_ANCESTRY:
        case PROTO_ANSWERS:
        case PROTO_ABOUT:
        case PROTO_ADF:
        case PROTO_ADOBE:
        case PROTO_AFP:
        case PROTO_ALIBABA:
        case PROTO_AMAZON:
        case PROTO_AOL:
        case PROTO_APPLE:
        case PROTO_ASK:
        case PROTO_AVG:
        case PROTO_AVI:
        case PROTO_AWEBER:
        case PROTO_AWS:
        case PROTO_BANKOFAMERICA:
        case PROTO_BARNESANDNOBLE:
        case PROTO_BBB:
        case PROTO_BESTBUY:
        case PROTO_BIBLEGATEWAY:
        case PROTO_BILD:
        case PROTO_BLEACHERREPORT:
        case PROTO_BLOGFA:
        case PROTO_BODYBUILDING:
        case PROTO_BOOKING:
        case PROTO_CBSSPORTS:
        case PROTO_CENT:
        case PROTO_CHANGE:
        case PROTO_CHASE:
        case PROTO_BABYLON:
        case PROTO_BAIDU:
        case PROTO_BBC_ONLINE:
        case PROTO_BING:
        case PROTO_BLOGGER:
        case PROTO_BLOGSPOT:
        case PROTO_CHINAZ:
        case PROTO_CNN:
        case PROTO_CLICKSOR:
        case PROTO_CNZZ:
        case PROTO_COMCAST:
        case PROTO_COPYSCAPE:
        case PROTO_CORREIOS:
        case PROTO_DAILYMAIL:
        case PROTO_DEVIANTART:
        case PROTO_DIGG:
        case PROTO_CONDUIT:
        case PROTO_CRAIGSLIST:
        case PROTO_DONANIMHABER:
        case PROTO_DOUBAN:
        case PROTO_DOUBLECLICK:
        case PROTO_EHOW:
        case PROTO_EKSISOZLUK:
        case PROTO_ETSY:
        case PROTO_EUROPA:
        case PROTO_EUROSPORT:
        case PROTO_FIVERR:
        case PROTO_FOURSQUARE:
        case PROTO_FOX:
        case PROTO_FREE:
        case PROTO_GAP:
        case PROTO_GARANTI:
        case PROTO_GAZETEVATAN:
        case PROTO_GIGAPETA:
        case PROTO_GITHUB:
        case PROTO_GITTIGIDIYOR:
        case PROTO_GLOBO:
        case PROTO_EBAY:
        case PROTO_ESPN:
        case PROTO_FACEBOOK:
        case PROTO_FC2:
        case PROTO_FLASH:
        case PROTO_FLICKR:
        case PROTO_GO:
        case PROTO_GODADDY:
        case PROTO_GOOGLE:
        case PROTO_GOO:
        case PROTO_GROUPON:
        case PROTO_GUARDIAN:
        case PROTO_HABERTURK:
        case PROTO_HEPSIBURADA:
        case PROTO_HI5:
        case PROTO_HOMEDEPOT:
        case PROTO_HOOTSUITE:
        case PROTO_HURRIYET:
        case PROTO_GOOGLE_MAPS:
        case PROTO_GOOGLE_USER_CONTENT:
        case PROTO_HAO123:
        case PROTO_HTTP:
        case PROTO_HTTP_CONNECT:
        case PROTO_HTTP_PROXY:
        case PROTO_HUFFINGTONPOST:
        case PROTO_I23V5:
        case PROTO_IKEA:
        case PROTO_IMGUR:
        case PROTO_INCREDIBAR:
        case PROTO_INDIATIMES:
        case PROTO_IRS:
        case PROTO_JAPANPOST:
        case PROTO_KAT:
        case PROTO_KOHLS:
        case PROTO_LEGACY:
        case PROTO_LETV:
        case PROTO_LIVE:
        case PROTO_LIVEDOOR:
        case PROTO_IFENG:
        case PROTO_INSTAGRAM:
        case PROTO_IMDB:
        case PROTO_LINKEDIN:
        case PROTO_LIVEINTERNET:
        case PROTO_LIVEJOURNAL:
        case PROTO_LIVESCORE:
        case PROTO_LIVINGSOCIAL:
        case PROTO_LOWES:
        case PROTO_MACYS:
        case PROTO_MATCH:
        case PROTO_MILLIYET:
        case PROTO_MLBASEBALL:
        case PROTO_MOZILLA:
        case PROTO_MULTIPLY:
        case PROTO_MYNET:
        case PROTO_MYSPACE:
        case PROTO_MYWEBSEARCH:
        case PROTO_NBA:
        case PROTO_NEOBUX:
        case PROTO_LIVEJASMIN:
        case PROTO_MICROSOFT:
        case PROTO_ODNOKLASSNIKI:
        case PROTO_PAYPAL:
        case PROTO_NEWEGG:
        case PROTO_NEWSMAX:
        case PROTO_NFL:
        case PROTO_NICOVIDEO:
        case PROTO_NIH:
        case PROTO_NORDSTROM:
        case PROTO_NYTIMES:
        case PROTO_ONET:
        case PROTO_ORANGEDONKEY:
        case PROTO_OUTBRAIN:
        case PROTO_OVERSTOCK:
        case PROTO_PCONLINE:
        case PROTO_PHOTOBUCKET:
        case PROTO_PINTEREST:
        case PROTO_PREMIERLEAGUE:
        case PROTO_R10:
        case PROTO_REDDIT:
        case PROTO_REFERENCE:
        case PROTO_RENREN:
        case PROTO_SABAH:
        case PROTO_SAHIBINDEN:
        case PROTO_SALESFORCE:
        case PROTO_SALON:
        case PROTO_SEARCHNU:
        case PROTO_SEARCH_RESULTS:
        case PROTO_SEARS:
        case PROTO_SECURESERVER:
        case PROTO_POPO:
        case PROTO_PORNHUB:
        case PROTO_QQ:
        case PROTO_QUICKTIME:
        case PROTO_RAKUTEN:
        case PROTO_REDTUBE:
        case PROTO_SINA:
        case PROTO_SITEADVISOR:
        case PROTO_SKY:
        case PROTO_SKYROCK:
        case PROTO_SKYSPORTS:
        case PROTO_SLATE:
        case PROTO_SLIDESHARE:
        case PROTO_SOFTONIC:
        case PROTO_SOUNDCLOUD:
        case PROTO_SOURGEFORGE:
        case PROTO_SPIEGEL:
        case PROTO_SPORX:
        case PROTO_SQUIDOO:
        case PROTO_SOCRATES:
        case PROTO_SOGOU:
        case PROTO_SOHU:
        case PROTO_SOSO:
        case PROTO_STACK_OVERFLOW:
        case PROTO_TAOBAO:
        case PROTO_TCO:
        case PROTO_THE_PIRATE_BAY:
        case PROTO_TMALL:
        case PROTO_TUDOU:
        case PROTO_TUENTI:
        case PROTO_TUMBLR:
        case PROTO_STATCOUNTER:
        case PROTO_STUMBLEUPON:
        case PROTO_SULEKHA:
        case PROTO_TAGGED:
        case PROTO_TARGET:
        case PROTO_THEMEFOREST:
        case PROTO_TIANYA:
        case PROTO_TUBE8:
        case PROTO_UCOZ:
        case PROTO_USDEPARTMENTOFSTATE:
        case PROTO_VIADEO:
        case PROTO_TWITTER:
        case PROTO_UOL:
        case PROTO_USENET:
        case PROTO_VK:
        case PROTO_WEIBO:
        case PROTO_WIKIPEDIA:
        case PROTO_WINUPDATE:
        case PROTO_WINDOWSLIVE:
        case PROTO_WINDOWSMEDIA:
        case PROTO_WORDPRESS_ORG:
        case PROTO_XHAMSTER:
        case PROTO_XVIDEOS:
        case PROTO_VKONTAKTE:
        case PROTO_WALMART:
        case PROTO_WARRIORFORUM:
        case PROTO_WAYN:
        case PROTO_WEATHER:
        case PROTO_WEEKLYSTANDARD:
        case PROTO_WELLSFARGO:
        case PROTO_WIGETMEDIA:
        case PROTO_WIKIA:
        case PROTO_WIKIMEDIA:
        case PROTO_WILLIAMHILL:
        case PROTO_WWE:
        case PROTO_XING:
        case PROTO_XINHUANET:
        case PROTO_XNXX:
        case PROTO_YELP:
        case PROTO_ZAPPOS:
        case PROTO_ZOL:
        case PROTO_YAHOO:
        case PROTO_YANDEX:
        case PROTO_YOUKU:
        case PROTO_YOUPORN:
        case PROTO_ZEDO:
        case PROTO_BUZZNET:
        case PROTO_COMEDY:
        case PROTO_RAMBLER:
        case PROTO_SMUGMUG:
        case PROTO_ARCHIEVE:
        case PROTO_CITYNEWS:
        case PROTO_SCIENCESTAGE:
        case PROTO_ONEWORLD:
        case PROTO_DISQUS:
        case PROTO_BLOGCU:
        case PROTO_EKOLEY:
        case PROTO_500PX:
        case PROTO_FOTKI:
        case PROTO_FOTOLOG:
        case PROTO_JALBUM:
        case PROTO_LOCKERZ:
        case PROTO_PANORAMIO:
        case PROTO_SNAPFISH:
        case PROTO_WEBSHOTS:
        case PROTO_BREAK:
        case PROTO_ENGAGEMEDIA:
        case PROTO_GCM:
            return PROTO_CLASS_WEB;
        case PROTO_888POKER:
        case PROTO_ANGRYBIRDS:
        case PROTO_ARMAGETRON:
        case PROTO_BATTLEFIELD:
        case PROTO_ELECTRONICSARTS:
        case PROTO_GAMEFAQS:
        case PROTO_GAMESPOT:
        case PROTO_BATTLENET:
        case PROTO_BETFAIR:
        case PROTO_CHESS:
        case PROTO_CROSSFIRE:
        case PROTO_DOFUS:
        case PROTO_FIESTA:
        case PROTO_FLORENSIA:
        case PROTO_GUILDWARS:
        case PROTO_HALFLIFE2:
        case PROTO_IGN:
        case PROTO_KING:
        case PROTO_KONGREGATE:
        case PROTO_LEAGUEOFLEGENDS:
        case PROTO_MINECRAFT:
        case PROTO_MINICLIP:
        case PROTO_MMO_CHAMPION:
        case PROTO_MAPLESTORY:
        case PROTO_QUAKE:
        case PROTO_PCH:
        case PROTO_PLAYSTATION:
        case PROTO_POGO:
        case PROTO_ROBLOX:
        case PROTO_ROVIO:
        case PROTO_SECONDLIFE:
        case PROTO_STEAM:
        case PROTO_UBI:
        case PROTO_WARCRAFT3:
        case PROTO_WORLD_OF_KUNG_FU:
        case PROTO_WORLDOFWARCRAFT:
        case PROTO_WOWHEAD:
        case PROTO_XBOX:
        case PROTO_YAHOOGAMES:
        case PROTO_ZYNGA:
        case PROTO_GAMEFORGE:
        case PROTO_METIN2:
        case PROTO_OGAME:
        case PROTO_BATTLEKNIGHT:
        case PROTO_4STORY:
            return PROTO_CLASS_GAMING;
        case PROTO_AIMINI:
        case PROTO_APPLEJUICE:
        case PROTO_BITTORRENT:
        case PROTO_DIRECTCONNECT:
        case PROTO_EDONKEY:
        case PROTO_FASTTRACK:
        case PROTO_FILETOPIA:
        case PROTO_GNUTELLA:
        case PROTO_IMESH:
        case PROTO_KAZAA:
        case PROTO_MANOLITO:
        case PROTO_OPENFT:
        case PROTO_PANDO:
        case PROTO_SOULSEEK:
        case PROTO_STEALTHNET:
        case PROTO_THUNDER:
        case PROTO_TORRENTZ:
        case PROTO_WINMX:
            return PROTO_CLASS_P2P;
        case PROTO_IZLESENE:
        case PROTO_SEVENLOAD:
        case PROTO_MUBI:
        case PROTO_SCREENJUNKIES:
        case PROTO_COMEDYCENTRAL:
        case PROTO_CITYTV:
        case PROTO_VIDOOSH:
        case PROTO_AFREECA:
        case PROTO_WILDSCREEN:
        case PROTO_BLOGTV:
        case PROTO_HULU:
        case PROTO_MEVIO:
        case PROTO_LIVESTREAM:
        case PROTO_LIVELEAK:
        case PROTO_DEEZER:
        case PROTO_BLIPTV:
        case PROTO_RUTUBE:
        case PROTO_VIDEO_HOSTING:
        case PROTO_7DIGITAL:
        case PROTO_DAILYMOTION:
        case PROTO_FEIDIAN:
        case PROTO_GROOVESHARK:
        case PROTO_ICECAST:
        case PROTO_APPLE_ITUNES:
        case PROTO_KONTIKI:
        case PROTO_LASTFM:
        case PROTO_MMS:
        case PROTO_MOVE:
        case PROTO_MPEG:
        case PROTO_NETFLIX:
        case PROTO_OFF:
        case PROTO_OGG:
        case PROTO_REALMEDIA:
        case PROTO_SHAZAM:
        case PROTO_PPLIVE:
        case PROTO_PPSTREAM:
        case PROTO_QQLIVE:
        case PROTO_RTP:
        case PROTO_RTSP:
        case PROTO_SHOUTCAST:
        case PROTO_SOPCAST:
        case PROTO_SPOTIFY:
        case PROTO_TVANTS:
        case PROTO_TVUPLAYER:
        case PROTO_HTTP_APPLICATION_VEOHTV:
        case PROTO_VIMEO:
        case PROTO_USTREAM:
        case PROTO_YOUTUBE:
        case PROTO_ZATTOO:
            return PROTO_CLASS_STREAMING;
        case PROTO_AIM:
        case PROTO_BADOO:
        case PROTO_FACETIME:
        case PROTO_GOSMS:
        case PROTO_GTALK:
        case PROTO_OSCAR:
        case PROTO_IRC:
        case PROTO_UNENCRYPED_JABBER:
        case PROTO_IMESSAGE:
        case PROTO_KAKAO:
        case PROTO_MEEBO:
        case PROTO_WHATSAPP:
        case PROTO_GADUGADU:
        case PROTO_IAX:
        case PROTO_MGCP:
        case PROTO_MSN:
        case PROTO_SIP:
        case PROTO_SKYPE:
        case PROTO_TRUPHONE:
        case PROTO_VIBER:
        case PROTO_YAHOOMSG:
        case PROTO_TANGO:
        case PROTO_WECHAT:
        case PROTO_LINE:
        case PROTO_FBMSG:
            return PROTO_CLASS_CONVERSATIONAL;
        case PROTO_IMAP:
        case PROTO_IMAPS:
        case PROTO_POP:
        case PROTO_POPS:
        case PROTO_SMTP:
        case PROTO_SMTPS:
        case PROTO_GMAIL:
        case PROTO_HOTMAIL:
        case PROTO_LIVEMAIL:
        case PROTO_MAIL_RU:
        case PROTO_YAHOOMAIL:
            return PROTO_CLASS_MAIL;
        case PROTO_DROPBOX:
        case PROTO_BOX:
        case PROTO_SKYDRIVE:
        case PROTO_APPLE_ICLOUD:
            return PROTO_CLASS_CLOUD_STORAGE;
        case PROTO_FTP:
        case PROTO_NFS:
        case PROTO_SMB:
        case PROTO_TFTP:
            return PROTO_CLASS_FILETRANSFER;
        case PROTO_DIRECT_DOWNLOAD_LINK:
        case PROTO_MEGA:
        case PROTO_MEDIAFIRE:
            return PROTO_CLASS_DDL;
        case PROTO_MSSQL:
        case PROTO_MYSQL:
        case PROTO_POSTGRES:
        case PROTO_TDS:
            return PROTO_CLASS_DB;
        case PROTO_GRE:
        case PROTO_IP_IN_IP:
        case PROTO_PPP:
        case PROTO_PPPOE:
        case PROTO_PPTP:
        case PROTO_ETHERIP:
        case PROTO_IPX_IN_IP:
        case PROTO_MPLS_IN_IP:
        case PROTO_GTP:
        case PROTO_GTP2:
        case PROTO_L2TP:
            return PROTO_CLASS_TUNNEL;
        case PROTO_ESP:
        case PROTO_8021Q:
        case PROTO_AH:
        case PROTO_ARP:
        case PROTO_BATMAN:
        case PROTO_BGP:
        case PROTO_DHCP:
        case PROTO_DHCPV6:
        case PROTO_DNS:
        case PROTO_EGP:
        case PROTO_ETHERNET:
        case PROTO_ICMP:
        case PROTO_ICMPV6:
        case PROTO_IGMP:
        case PROTO_IP:
        case PROTO_IPV6:
        case PROTO_IPP:
        case PROTO_IPSEC:
        case PROTO_KERBEROS:
        case PROTO_LDAP:
        case PROTO_MDNS:
        case PROTO_MANET:
        case PROTO_NETBIOS:
        case PROTO_NETFLOW:
        case PROTO_NTP:
        case PROTO_OSPF:
        case PROTO_RADIUS:
        case PROTO_SCTP:
        case PROTO_SFLOW:
        case PROTO_SNMP:
        case PROTO_SSDP:
        case PROTO_SSL:
        case PROTO_STUN:
        case PROTO_SYSLOG:
        case PROTO_TCP:
        case PROTO_TLS:
        case PROTO_UDP:
        case PROTO_UDPLITE:
        case PROTO_3PC:
        case PROTO_ANY_0HOP:
        case PROTO_ANY_DFS:
        case PROTO_ANY_HIP:
        case PROTO_ANY_LOCAL:
        case PROTO_ANY_PES:
        case PROTO_ARGUS:
        case PROTO_ARIS:
        case PROTO_AX_25:
        case PROTO_BBN_RCC_MON:
        case PROTO_BNA:
        case PROTO_BR_SAT_MON:
        case PROTO_CBT:
        case PROTO_CFTP:
        case PROTO_CHAOS:
        case PROTO_COMPAQ_PEER:
        case PROTO_CPHB:
        case PROTO_CPNX:
        case PROTO_CRTP:
        case PROTO_CRUDP:
        case PROTO_DCCP:
        case PROTO_DCN_MEAS:
        case PROTO_DDP:
        case PROTO_DDX:
        case PROTO_DGP:
        case PROTO_EIGRP:
        case PROTO_EMCON:
        case PROTO_ENCAP:
        case PROTO_FC:
        case PROTO_FIRE:
        case PROTO_GGP:
        case PROTO_GMTP:
        case PROTO_HIP:
        case PROTO_HMP:
        case PROTO_I_NLSP:
        case PROTO_IATP:
        case PROTO_IDPR:
        case PROTO_IDPR_CMTP:
        case PROTO_IDRP:
        case PROTO_IFMP:
        case PROTO_IGP:
        case PROTO_IL:
        case PROTO_IPCOMP:
        case PROTO_IPCV:
        case PROTO_IPLT:
        case PROTO_IPPC:
        case PROTO_IPTM:
        case PROTO_IRTP:
        case PROTO_IS_IS:
        case PROTO_ISO_IP:
        case PROTO_ISO_TP4:
        case PROTO_KRYPTOLAN:
        case PROTO_LARP:
        case PROTO_LEAF_1:
        case PROTO_LEAF_2:
        case PROTO_MERIT_INP:
        case PROTO_MFE_NSP:
        case PROTO_MHRP:
        case PROTO_MICP:
        case PROTO_MOBILE:
        case PROTO_MOBILITY_HEADER:
        case PROTO_MTP:
        case PROTO_MUX:
        case PROTO_NARP:
        case PROTO_NETBLT:
        case PROTO_NSFNET_IGP:
        case PROTO_NVP_II:
        case PROTO_PGM:
        case PROTO_PIM:
        case PROTO_PIPE:
        case PROTO_PNNI:
        case PROTO_PRM:
        case PROTO_PTP:
        case PROTO_PUP:
        case PROTO_PVP:
        case PROTO_QNX:
        case PROTO_RSVP:
        case PROTO_RSVP_E2E_IGNORE:
        case PROTO_RVD:
        case PROTO_SAT_EXPAK:
        case PROTO_SAT_MON:
        case PROTO_SCC_SP:
        case PROTO_SCPS:
        case PROTO_SDRP:
        case PROTO_SECURE_VMTP:
        case PROTO_SHIM6:
        case PROTO_SKIP:
        case PROTO_SM:
        case PROTO_SMP:
        case PROTO_SNP:
        case PROTO_SPRITE_RPC:
        case PROTO_SPS:
        case PROTO_SRP:
        case PROTO_SSCOPMCE:
        case PROTO_ST:
        case PROTO_STP:
        case PROTO_SUN_ND:
        case PROTO_SWIPE:
        case PROTO_TCF:
        case PROTO_TLSP:
        case PROTO_TP_PP:
        case PROTO_TRUNK_1:
        case PROTO_TRUNK_2:
        case PROTO_UTI:
        case PROTO_VINES:
        case PROTO_VISA:
        case PROTO_VMTP:
        case PROTO_VRRP:
        case PROTO_WB_EXPAK:
        case PROTO_WB_MON:
        case PROTO_WSN:
        case PROTO_XNET:
        case PROTO_XNS_IDP:
        case PROTO_XTP:
        case PROTO_SLL:
            return PROTO_CLASS_NETWORK;
        case PROTO_PCANYWHERE:
        case PROTO_RDP:
        case PROTO_VNC:
        case PROTO_SSH:
        case PROTO_TEAMVIEWER:
        case PROTO_TELNET:
        case PROTO_XDMCP:
            return PROTO_CLASS_REMOTE;
        case PROTO_CITRIX:
        case PROTO_CITRIXONLINE:
        case PROTO_DCERPC:
        case PROTO_WEBEX:
        case PROTO_HTTP_APPLICATION_ACTIVESYNC:
            return PROTO_CLASS_MISC;
        case PROTO_AKAMAI:
        case PROTO_CLOUDFRONT:
        case PROTO_BITGRAVITY:
        case PROTO_CACHEFLY:
        case PROTO_CDN77:
        case PROTO_CDNETWORKS:
        case PROTO_CHINACACHE:
        case PROTO_COTENDO:
        case PROTO_EDGECAST:
        case PROTO_FASTLY:
        case PROTO_HIGHWINDS:
        case PROTO_INTERNAP:
        case PROTO_LEVEL3:
        case PROTO_LIMELIGHT:
        case PROTO_MAXCDN:
        case PROTO_NETDNA:
        case PROTO_VOXEL:
        case PROTO_RACKSPACE:
            return PROTO_CLASS_CDN;
        case PROTO_UNKNOWN:
        default:
            return PROTO_CLASS_UNKOWN;
    }
}

static inline char * get_application_class_name_by_protocol_id(int id) {
    static char *classes[] = {PROTO_CLASS_LABELS};
    int class_id = get_application_class_by_protocol_id(id);
    return classes[class_id];
}

#ifdef __cplusplus
}
#endif

#endif /* MMT_TCPIP_H */
