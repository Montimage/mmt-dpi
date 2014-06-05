/*
 * File:   mmt_contents_defs.h
 * Author: Bachar Wehbi
 *
 * Created on 1 octobre 2012, 11:17
 */

#ifndef MMT_CONTENTS_DEFS_H
#define MMT_CONTENTS_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#define MMT_CONTENT_CDN 1
#define MMT_CONTENT_ADULT 2
#define MMT_CONTENT_IMAGE 4
#define MMT_CONTENT_VIDEO 8
#define MMT_CONTENT_AUDIO 16
#define MMT_CONTENT_CONVERSATIONAL 32

#define MMT_CONTENT_FAMILY_UNSPECIFIED          0
#define MMT_CONTENT_FAMILY_APPLICATION          1
#define MMT_CONTENT_FAMILY_IMAGE                2
#define MMT_CONTENT_FAMILY_AUDIO                3
#define MMT_CONTENT_FAMILY_VIDEO                4
#define MMT_CONTENT_FAMILY_MESSAGE              5
#define MMT_CONTENT_FAMILY_MODEL                6
#define MMT_CONTENT_FAMILY_MULTIPART            7
#define MMT_CONTENT_FAMILY_TEXT                 8
#define MMT_CONTENT_FAMILY_CONVERSATION         9

#define MMT_CONTENT_LONG_LABELS  "", "Application", "Image", "Audio", "Video", "Message", "Model", "Multipart", "Text", "Conversation"
#define MMT_CONTENT_SHORT_LABELS "", "application", "image", "audio", "video", "message", "model", "multipart", "text", "conversation"

#define MMT_CONTENT_TYPE_ATOM_XML           10000
#define MMT_CONTENT_TYPE_ECMASCRIPT         10001
#define MMT_CONTENT_TYPE_JAVASCRIPT         10002
#define MMT_CONTENT_TYPE_EDI_X12            10003
#define MMT_CONTENT_TYPE_EDIFACT            10004
#define MMT_CONTENT_TYPE_JSON               10005
#define MMT_CONTENT_TYPE_OCTET_STREAM       10006
#define MMT_CONTENT_TYPE_OGG                10007
#define MMT_CONTENT_TYPE_PDF                10008
#define MMT_CONTENT_TYPE_POSTSCRIPT         10009
#define MMT_CONTENT_TYPE_RDF_XML            10010
#define MMT_CONTENT_TYPE_RSS_XML            10011
#define MMT_CONTENT_TYPE_SOAP_XML           10012
#define MMT_CONTENT_TYPE_FONT_WOFF          10013
#define MMT_CONTENT_TYPE_X_FONT_WOFF        10014
#define MMT_CONTENT_TYPE_XHTML_XML          10015
#define MMT_CONTENT_TYPE_XML_DTD            10016
#define MMT_CONTENT_TYPE_XOP_XML            10017
#define MMT_CONTENT_TYPE_ZIP                10018
#define MMT_CONTENT_TYPE_GZIP               10019
#define MMT_CONTENT_TYPE_BASIC              10020
#define MMT_CONTENT_TYPE_L24                10021
#define MMT_CONTENT_TYPE_MP4                10022
#define MMT_CONTENT_TYPE_MPEG               10023
#define MMT_CONTENT_TYPE_VORBIS             10024
#define MMT_CONTENT_TYPE_VND_RN_REALAUDIO   10025
#define MMT_CONTENT_TYPE_VND_WAVE           10026
#define MMT_CONTENT_TYPE_WEBM               10027
#define MMT_CONTENT_TYPE_GIF                10028
#define MMT_CONTENT_TYPE_JPEG               10029
#define MMT_CONTENT_TYPE_PJPEG              10030
#define MMT_CONTENT_TYPE_PNG                10031
#define MMT_CONTENT_TYPE_SVG_XML            10032
#define MMT_CONTENT_TYPE_TIFF               10033
#define MMT_CONTENT_TYPE_VND_MICROSOFT_ICON 10034
#define MMT_CONTENT_TYPE_HTTP               10035
#define MMT_CONTENT_TYPE_IMDN_XML           10036
#define MMT_CONTENT_TYPE_PARTIAL            10037
#define MMT_CONTENT_TYPE_RFC822             10038
#define MMT_CONTENT_TYPE_EXAMPLE            10039
#define MMT_CONTENT_TYPE_IGES               10040
#define MMT_CONTENT_TYPE_MESH               10041
#define MMT_CONTENT_TYPE_VRML               10042
#define MMT_CONTENT_TYPE_X3D_BINARY         10043
#define MMT_CONTENT_TYPE_X3D_VRML           10044
#define MMT_CONTENT_TYPE_X3D_XML            10045
#define MMT_CONTENT_TYPE_MIXED              10046
#define MMT_CONTENT_TYPE_ALTERNATIVE        10047
#define MMT_CONTENT_TYPE_RELATED            10048
#define MMT_CONTENT_TYPE_FORM_DATA          10049
#define MMT_CONTENT_TYPE_SIGNED             10050
#define MMT_CONTENT_TYPE_ENCRYPTED          10051
#define MMT_CONTENT_TYPE_CMD                10052
#define MMT_CONTENT_TYPE_CSS                10053
#define MMT_CONTENT_TYPE_CSV                10054
#define MMT_CONTENT_TYPE_HTML               10055
#define MMT_CONTENT_TYPE_PLAIN              10056
#define MMT_CONTENT_TYPE_VCARD              10057
#define MMT_CONTENT_TYPE_XML                10058
#define MMT_CONTENT_TYPE_QUICKTIME          10059
#define MMT_CONTENT_TYPE_X_MATROSKA         10060
#define MMT_CONTENT_TYPE_X_MS_WMV           10061
#define MMT_CONTENT_TYPE_X_FLV              10062

#define MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_TEXT                                   10063
#define MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_SPREADSHEET                            10064
#define MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_PRESENTATION                           10065
#define MMT_CONTENT_TYPE_VND_OASIS_OPENDOCUMENT_GRAPHICS                               10066
#define MMT_CONTENT_TYPE_VND_MS_EXCEL                                                  10067
#define MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_SPREADSHEETML_SHEET         10068
#define MMT_CONTENT_TYPE_VND_MS_POWERPOINT                                             10069
#define MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_PRESENTATIONML_PRESENTATION 10070
#define MMT_CONTENT_TYPE_VND_OPENXMLFORMATS_OFFICEDOCUMENT_WORDPROCESSINGML_DOCUMENT   10071
#define MMT_CONTENT_TYPE_VND_MOZILLA_XUL_XML                                           10072
#define MMT_CONTENT_TYPE_VND_GOOGLE_EARTH_KML_XML                                      10073

#define MMT_CONTENT_TYPE_X_WWW_FORM_URLENCODED 10074
#define MMT_CONTENT_TYPE_X_DVI                 10075
#define MMT_CONTENT_TYPE_X_LATEX               10076
#define MMT_CONTENT_TYPE_X_FONT_TTF            10077
#define MMT_CONTENT_TYPE_X_SHOCKWAVE_FLASH     10078
#define MMT_CONTENT_TYPE_X_STUFFIT             10079
#define MMT_CONTENT_TYPE_X_RAR_COMPRESSED      10080
#define MMT_CONTENT_TYPE_X_TAR                 10081
#define MMT_CONTENT_TYPE_X_GWT_RPC             10082
#define MMT_CONTENT_TYPE_X_JQUERY_TMPL         10083
#define MMT_CONTENT_TYPE_X_JAVASCRIPT          10084
#define MMT_CONTENT_TYPE_X_DEB                 10085
#define MMT_CONTENT_TYPE_X_AAC                 10086
#define MMT_CONTENT_TYPE_X_CAF                 10087
#define MMT_CONTENT_TYPE_X_MPEG_URL            10088
#define MMT_CONTENT_TYPE_X_XCF                 10089

#define MMT_CONTENT_TYPE_X_PKCS12              10090
#define MMT_CONTENT_TYPE_X_PKCS7_CERTIFICATES  10091
#define MMT_CONTENT_TYPE_X_PKCS7_CERTREQRESP   10092
#define MMT_CONTENT_TYPE_X_PKCS7_MIME          10093
#define MMT_CONTENT_TYPE_X_PKCS7_SIGNATURE     10094
#define MMT_CONTENT_TYPE_M4V                   10095
#define MMT_CONTENT_TYPE_REALAUDIO             10096
#define MMT_CONTENT_TYPE_REALMEDIA             10097

#ifdef __cplusplus
}
#endif

#endif /* MMT_CONTENTS_DEFS_H */
