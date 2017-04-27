#include "mmt_common_internal_include.h"

/*
 */
static inline int _mmt_case_sensitive_reverse_hostname_matching(const char *hostname, const char *url, size_t hostname_len, size_t url_len) {
    if (hostname_len < url_len - 1) {
        return 0; //No match
    }

    const char * hnr = &hostname[ 0 ];
    const char * urlr = &url[ 1 ];

    while (*hnr && *hnr == *urlr && url_len && hostname_len) {
        url_len--;
        hostname_len--;
        hnr++;
        urlr++;
    }
    if (0 == url_len || hostname_len == 0)
        return 1; /* they are equal this far */

    return 0;
}

int mmt_case_sensitive_reverse_hostname_matching(const char *hostname, const char *url, size_t hostname_len, size_t url_len) {
    return _mmt_case_sensitive_reverse_hostname_matching( hostname, url, hostname_len, url_len);
}


static const protocol_match doted_host_names[] = {
    {".gmail.com", PROTO_GMAIL, MMT_STATICSTRING_LEN(".gmail.com")},
    {".talk.google.com", PROTO_GTALK, MMT_STATICSTRING_LEN(".talk.google.com")},
    {".mail.google.com", PROTO_GMAIL, MMT_STATICSTRING_LEN(".mail.google.com")},
    {".maps.google.com", PROTO_GOOGLE_MAPS, MMT_STATICSTRING_LEN(".maps.google.com")},
    {".maps.gstatic.com", PROTO_GOOGLE_MAPS, MMT_STATICSTRING_LEN(".maps.gstatic.com")},
    {".docs.google.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".docs.google.com")},
    {".drive.google.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".drive.google.com")},
    {".google.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com")},
    {".google.co.in", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.in")},
    {".google.de", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.de")},
    {".google.com.hk", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.hk")},
    {".google.co.jp", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.jp")},
    {".google.co.uk", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.uk")},
    {".google.fr", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.fr")},
    {".google.com.br", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.br")},
    {".google.es", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.es")},
    {".google.it", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.it")},
    {".google.ru", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.ru")},
    {".google.com.mx", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.mx")},
    {".google.ca", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.ca")},
    {".google.co.id", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.id")},
    {".google.com.tr", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.tr")},
    {".google.com.au", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.au")},
    {".google.pl", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.pl")},
    {".google.nl", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.nl")},
    {".google.com.sa", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.sa")},
    {".google.com.ar", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.ar")},
    {".google.com.pk", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.pk")},
    {".google.com.eg", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.eg")},
    {".google.cn", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.cn")},
    {".google.co.th", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.th")},
    {".google.co.za", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.za")},
    {".google.co.ve", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.co.ve")},
    {".google.com.my", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google.com.my")},
    {".gstatic.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".gstatic.com")},
    {".googleapis.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".googleapis.com")},
    {".googlesyndication.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".googlesyndication.com")},
    {".google-analytics.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".google-analytics.com")},
    {".googleadservices.com", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".googleadservices.com")},
    {".googleusercontent.com", PROTO_GOOGLE_USER_CONTENT, MMT_STATICSTRING_LEN(".googleusercontent.com")},
    {".2mdn.net", PROTO_GOOGLE, MMT_STATICSTRING_LEN(".2mdn.net")},

    {".facebook.com", PROTO_FACEBOOK, MMT_STATICSTRING_LEN(".facebook.com")},
    {".facebook.net", PROTO_FACEBOOK, MMT_STATICSTRING_LEN(".facebook.net")},
    {".fbcdn.net", PROTO_FACEBOOK, MMT_STATICSTRING_LEN(".fbcdn.net")},
    {".fbcdn-video-a.akamaihd.net", PROTO_FACEBOOK, MMT_STATICSTRING_LEN(".fbcdn-video-a.akamaihd.net"), MMT_CONTENT_CDN},
    {".fbcdn-profile-a.akamaihd.net", PROTO_FACEBOOK, MMT_STATICSTRING_LEN(".fbcdn-profile-a.akamaihd.net"), MMT_CONTENT_CDN},
    {".fbsbx.com", PROTO_FACEBOOK, MMT_STATICSTRING_LEN(".fbsbx.com")},

    {".youtube.com", PROTO_YOUTUBE, MMT_STATICSTRING_LEN(".youtube.com")},
    {".ytimg.com", PROTO_YOUTUBE, MMT_STATICSTRING_LEN(".ytimg.com")},

    {".storage.msn.com", PROTO_SKYDRIVE, MMT_STATICSTRING_LEN(".storage.msn.com")},
    {".livefilestore.com", PROTO_SKYDRIVE, MMT_STATICSTRING_LEN(".livefilestore.com")},
    {".storage.live.com", PROTO_SKYDRIVE, MMT_STATICSTRING_LEN(".storage.live.com")},
    {".skydrive.live.com", PROTO_SKYDRIVE, MMT_STATICSTRING_LEN(".skydrive.live.com")},
    {".skydrive.com", PROTO_SKYDRIVE, MMT_STATICSTRING_LEN(".skydrive.com")},
    {".messenger.live.com", PROTO_MSN, MMT_STATICSTRING_LEN(".messenger.live.com")},
    {".live.com", PROTO_LIVE, MMT_STATICSTRING_LEN(".live.com")},
    {".wlxrs.com", PROTO_LIVE, MMT_STATICSTRING_LEN(".wlxrs.com")},
    {".mail.live.com", PROTO_LIVEMAIL, MMT_STATICSTRING_LEN(".mail.live.com")},
    {".outlook.com", PROTO_LIVEMAIL, MMT_STATICSTRING_LEN(".outlook.com")},
    {".msn.com", PROTO_MSN, MMT_STATICSTRING_LEN(".msn.com")},
    {".msn.ca", PROTO_MSN, MMT_STATICSTRING_LEN(".msn.ca")},
    {".msn.co.jp", PROTO_MSN, MMT_STATICSTRING_LEN(".msn.co.jp")},

    {".msg.yahoo.com", PROTO_YAHOOMSG, MMT_STATICSTRING_LEN(".msg.yahoo.com")},
    {".mail.yahoo.com", PROTO_YAHOOMAIL, MMT_STATICSTRING_LEN(".mail.yahoo.com")},
    {".yahoo.com", PROTO_YAHOO, MMT_STATICSTRING_LEN(".yahoo.com")},
    {".yahoo.co.jp", PROTO_YAHOO, MMT_STATICSTRING_LEN(".yahoo.co.jp")},
    {".yimg.com", PROTO_YAHOO, MMT_STATICSTRING_LEN(".yimg.com")},

    {".wikipedia.org", PROTO_WIKIPEDIA, MMT_STATICSTRING_LEN(".wikipedia.org")},

    {".aws.amazon.com", PROTO_AWS, MMT_STATICSTRING_LEN(".aws.amazon.com")},
    {".amazonaws.com", PROTO_AWS, MMT_STATICSTRING_LEN(".amazonaws.com")},
    {".amazon.com", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.com")},
    {".amazon.it", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.it")},
    {".amazon.es", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.es")},
    {".amazon.de", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.de")},
    {".amazon.co.uk", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.co.uk")},
    {".amazon.fr", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.fr")},
    {".amazon.co.jp", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.co.jp")},
    {".amazon.de", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.de")},
    {".amazon.co.uk", PROTO_AMAZON, MMT_STATICSTRING_LEN(".amazon.co.uk")},

    {".twitter.com", PROTO_TWITTER, MMT_STATICSTRING_LEN(".twitter.com")},
    {".twttr.com", PROTO_TWITTER, MMT_STATICSTRING_LEN(".twttr.com")},
    {".twimg.com", PROTO_TWITTER, MMT_STATICSTRING_LEN(".twimg.com"), MMT_CONTENT_IMAGE},

    {".blogspot.com", PROTO_BLOGSPOT, MMT_STATICSTRING_LEN(".blogspot.com")},
    {".blogspot.in", PROTO_BLOGSPOT, MMT_STATICSTRING_LEN(".blogspot.in")},
    {".bp.blogspot.com", PROTO_BLOGSPOT, MMT_STATICSTRING_LEN(".bp.blogspot.com")},
    {".blogspot.com.br", PROTO_BLOGSPOT, MMT_STATICSTRING_LEN(".blogspot.com.br")},

    {".linkedin.com", PROTO_LINKEDIN, MMT_STATICSTRING_LEN(".linkedin.com")},

    {".bing.com", PROTO_BING, MMT_STATICSTRING_LEN(".bing.com")},

    {".itunes.apple.com", PROTO_APPLE_ITUNES, MMT_STATICSTRING_LEN(".itunes.apple.com")},
    {".apple.com", PROTO_APPLE, MMT_STATICSTRING_LEN(".apple.com")},
    {".mzstatic.com", PROTO_APPLE, MMT_STATICSTRING_LEN(".mzstatic.com")},

    {".dailymotion.com", PROTO_DAILYMOTION, MMT_STATICSTRING_LEN(".dailymotion.com")},
    {".dmcdn.net", PROTO_DAILYMOTION, MMT_STATICSTRING_LEN(".dmcdn.net")},

    {".dropbox.com", PROTO_DROPBOX, MMT_STATICSTRING_LEN(".dropbox.com")},

    {".cloudfront.net", PROTO_CLOUDFRONT, MMT_STATICSTRING_LEN(".cloudfront.net"), MMT_CONTENT_CDN},
    {".msecnd.net", PROTO_MSCDN, MMT_STATICSTRING_LEN(".msecnd.net")},
    {".akamai.com", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akamai.com"), MMT_CONTENT_CDN},
    {".akamai.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akamai.net"), MMT_CONTENT_CDN},
    {".akamaiedge.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akamaiedge.net"), MMT_CONTENT_CDN},
    {".akamaihd.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akamaihd.net"), MMT_CONTENT_CDN},
    {".edgesuite.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".edgesuite.net"), MMT_CONTENT_CDN},
    {".edgekey.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".edgekey.net"), MMT_CONTENT_CDN},
    {".srip.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".srip.net"), MMT_CONTENT_CDN},
    {".akamaitech.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akamaitech.net"), MMT_CONTENT_CDN},
    {".akadns.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akadns.net"), MMT_CONTENT_CDN},
    {".akam.net", PROTO_AKAMAI, MMT_STATICSTRING_LEN(".akam.net"), MMT_CONTENT_CDN},
    {".edgecastcdn.net", PROTO_EDGECAST, MMT_STATICSTRING_LEN(".edgecastcdn.net"), MMT_CONTENT_CDN},
    {".llnwd.net", PROTO_LIMELIGHT, MMT_STATICSTRING_LEN(".llnwd.net"), MMT_CONTENT_CDN},
    {".rackcdn.com", PROTO_RACKSPACE, MMT_STATICSTRING_LEN(".rackcdn.com"), MMT_CONTENT_CDN},
    {".netdna-cdn.com", PROTO_NETDNA, MMT_STATICSTRING_LEN(".netdna-cdn.com"), MMT_CONTENT_CDN},
    {".netdna.com", PROTO_NETDNA, MMT_STATICSTRING_LEN(".netdna.com"), MMT_CONTENT_CDN},

    {".163.com", PROTO_163, MMT_STATICSTRING_LEN(".163.com")},
    {".360.cn", PROTO_360, MMT_STATICSTRING_LEN(".360.cn")},
    {".360buy.com", PROTO_360BUY, MMT_STATICSTRING_LEN(".360buy.com")},
    {".56.com", PROTO_56, MMT_STATICSTRING_LEN(".56.com")},
    {".888.com", PROTO_888, MMT_STATICSTRING_LEN(".888.com")},
    {".about.com", PROTO_ABOUT, MMT_STATICSTRING_LEN(".about.com")},
    {".adcash.com", PROTO_ADCASH, MMT_STATICSTRING_LEN(".adcash.com")},
    {".addthisedge.com", PROTO_ADDTHIS, MMT_STATICSTRING_LEN(".addthisedge.com")},
    {".addthis.com", PROTO_ADDTHIS, MMT_STATICSTRING_LEN(".addthis.com")},
    {".adf.ly", PROTO_ADF, MMT_STATICSTRING_LEN(".adf.ly")},
    {".adobe.com", PROTO_ADOBE, MMT_STATICSTRING_LEN(".adobe.com")},
    {".afp.com", PROTO_AFP, MMT_STATICSTRING_LEN(".afp.com")},
    {".aim.com", PROTO_AIM, MMT_STATICSTRING_LEN(".aim.com")},
    {".aimini.net", PROTO_AIMINI, MMT_STATICSTRING_LEN(".aimini.net")},
    {".alibaba.com", PROTO_ALIBABA, MMT_STATICSTRING_LEN(".alibaba.com")},
    {".alipay.com", PROTO_ALIPAY, MMT_STATICSTRING_LEN(".alipay.com")},
    {".allegro.pl", PROTO_ALLEGRO, MMT_STATICSTRING_LEN(".allegro.pl")},
    {".ameblo.jp", PROTO_AMEBLO, MMT_STATICSTRING_LEN(".ameblo.jp")},
    {".ancestry.com", PROTO_ANCESTRY, MMT_STATICSTRING_LEN(".ancestry.com")},
    {".angrybirds.com", PROTO_ANGRYBIRDS, MMT_STATICSTRING_LEN(".angrybirds.com")},
    {".answers.com", PROTO_ANSWERS, MMT_STATICSTRING_LEN(".answers.com")},
    {".aol.com", PROTO_AOL, MMT_STATICSTRING_LEN(".aol.com")},
    {".ask.com", PROTO_ASK, MMT_STATICSTRING_LEN(".ask.com")},
    {".ask.fm", PROTO_ASK, MMT_STATICSTRING_LEN(".ask.fm")},
    {".avg.com", PROTO_AVG, MMT_STATICSTRING_LEN(".avg.com")},
    {".aweber.com", PROTO_AWEBER, MMT_STATICSTRING_LEN(".aweber.com")},
    {".babylon.com", PROTO_BABYLON, MMT_STATICSTRING_LEN(".babylon.com")},
    {".badoo.com", PROTO_BADOO, MMT_STATICSTRING_LEN(".badoo.com")},
    {".baidu.com", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.com")},
    {".baidu.jp", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.jp")},
    {".baidu.co", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.co")},
    {".baidu.cn", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.cn")},
    {".baidu.cm", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.cm")},
    {".baidu.co.th", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.co.th")},
    {".baidu.om", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.om")},
    {".baidu.com.bd", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.com.bd")},
    {".baidu.com.eg", PROTO_BAIDU, MMT_STATICSTRING_LEN(".baidu.com.eg")},
    {".bankofamerica.com", PROTO_BANKOFAMERICA, MMT_STATICSTRING_LEN(".bankofamerica.com")},
    {".barnesandnoble.com", PROTO_BARNESANDNOBLE, MMT_STATICSTRING_LEN(".barnesandnoble.com")},
    {".battlefield.com", PROTO_BATTLEFIELD, MMT_STATICSTRING_LEN(".battlefield.com")},
    {".battle.net", PROTO_BATTLENET, MMT_STATICSTRING_LEN(".battle.net")},
    {".bbb.org", PROTO_BBB, MMT_STATICSTRING_LEN(".bbb.org")},
    {".bbc.co.uk", PROTO_BBC_ONLINE, MMT_STATICSTRING_LEN(".bbc.co.uk")},
    {".bbci.co.uk", PROTO_BBC_ONLINE, MMT_STATICSTRING_LEN(".bbci.co.uk")},
    {".bestbuy.com", PROTO_BESTBUY, MMT_STATICSTRING_LEN(".bestbuy.com")},
    {".betfair.com", PROTO_BETFAIR, MMT_STATICSTRING_LEN(".betfair.com")},
    {".betfair.com.au", PROTO_BETFAIR, MMT_STATICSTRING_LEN(".betfair.com.au")},
    {".betfair.es", PROTO_BETFAIR, MMT_STATICSTRING_LEN(".betfair.es")},
    {".betfair.it", PROTO_BETFAIR, MMT_STATICSTRING_LEN(".betfair.it")},
    {".biblegateway.com", PROTO_BIBLEGATEWAY, MMT_STATICSTRING_LEN(".biblegateway.com")},
    {".bild.de", PROTO_BILD, MMT_STATICSTRING_LEN(".bild.de")},

    {".bleacherreport.com", PROTO_BLEACHERREPORT, MMT_STATICSTRING_LEN(".bleacherreport.com")},
    {".blogfa.com", PROTO_BLOGFA, MMT_STATICSTRING_LEN(".blogfa.com")},
    {".blogger.com", PROTO_BLOGGER, MMT_STATICSTRING_LEN(".blogger.com")},
    {".bodybuilding.com", PROTO_BODYBUILDING, MMT_STATICSTRING_LEN(".bodybuilding.com")},
    {".booking.com", PROTO_BOOKING, MMT_STATICSTRING_LEN(".booking.com")},
    {".cbssports.com", PROTO_CBSSPORTS, MMT_STATICSTRING_LEN(".cbssports.com")},
    {".cbssportsnetwork.com", PROTO_CBSSPORTS, MMT_STATICSTRING_LEN(".cbssportsnetwork.com")},
    {".cnet.com", PROTO_CENT, MMT_STATICSTRING_LEN(".cnet.com")},
    {".change.org", PROTO_CHANGE, MMT_STATICSTRING_LEN(".change.org")},
    {".chase.com", PROTO_CHASE, MMT_STATICSTRING_LEN(".chase.com")},
    {".chess.com", PROTO_CHESS, MMT_STATICSTRING_LEN(".chess.com")},
    {".chinaz.com", PROTO_CHINAZ, MMT_STATICSTRING_LEN(".chinaz.com")},
    {".citrixonline.com", PROTO_CITRIXONLINE, MMT_STATICSTRING_LEN(".citrixonline.com")},
    {".clicksor.com", PROTO_CLICKSOR, MMT_STATICSTRING_LEN(".clicksor.com")},
    {".cnn.com", PROTO_CNN, MMT_STATICSTRING_LEN(".cnn.com")},
    {".cnzz.com", PROTO_CNZZ, MMT_STATICSTRING_LEN(".cnzz.com")},
    {".comcast.net", PROTO_COMCAST, MMT_STATICSTRING_LEN(".comcast.net")},
    {".conduit.com", PROTO_CONDUIT, MMT_STATICSTRING_LEN(".conduit.com")},
    {".copyscape.com", PROTO_COPYSCAPE, MMT_STATICSTRING_LEN(".copyscape.com")},
    {".correios.com.br", PROTO_CORREIOS, MMT_STATICSTRING_LEN(".correios.com.br")},
    {".craigslist.org", PROTO_CRAIGSLIST, MMT_STATICSTRING_LEN(".craigslist.org")},
    {".crossfire1.ru", PROTO_CROSSFIRE, MMT_STATICSTRING_LEN(".crossfire1.ru")},
    {".dailymail.co.uk", PROTO_DAILYMAIL, MMT_STATICSTRING_LEN(".dailymail.co.uk")},

    {".deviantart.com", PROTO_DEVIANTART, MMT_STATICSTRING_LEN(".deviantart.com")},
    {".digg.com", PROTO_DIGG, MMT_STATICSTRING_LEN(".digg.com")},
    {".directconnectauto.com", PROTO_DIRECTCONNECT, MMT_STATICSTRING_LEN(".directconnectauto.com")},
    {".dofus.com", PROTO_DOFUS, MMT_STATICSTRING_LEN(".dofus.com")},
    {".donanimhaber.com", PROTO_DONANIMHABER, MMT_STATICSTRING_LEN(".donanimhaber.com")},
    {".douban.com", PROTO_DOUBAN, MMT_STATICSTRING_LEN(".douban.com")},
    {".doubleclick.com", PROTO_DOUBLECLICK, MMT_STATICSTRING_LEN(".doubleclick.com")},
    {".ebay.com", PROTO_EBAY, MMT_STATICSTRING_LEN(".ebay.com")},
    {".ebay.de", PROTO_EBAY, MMT_STATICSTRING_LEN(".ebay.de")},
    {".ebay.co.uk", PROTO_EBAY, MMT_STATICSTRING_LEN(".ebay.co.uk")},
    {".ebaystatic.com", PROTO_EBAY, MMT_STATICSTRING_LEN(".ebaystatic.com")},
    {".ebayimg.com", PROTO_EBAY, MMT_STATICSTRING_LEN(".ebayimg.com")},
    {".ehow.com", PROTO_EHOW, MMT_STATICSTRING_LEN(".ehow.com")},
    {".sourtimes.org", PROTO_EKSISOZLUK, MMT_STATICSTRING_LEN(".sourtimes.org")},
    {".ea.com", PROTO_ELECTRONICSARTS, MMT_STATICSTRING_LEN(".ea.com")},
    {".espn.go.com", PROTO_ESPN, MMT_STATICSTRING_LEN(".espn.go.com")},
    {".espncricinfo.com", PROTO_ESPN, MMT_STATICSTRING_LEN(".espncricinfo.com")},
    {".etsy.com", PROTO_ETSY, MMT_STATICSTRING_LEN(".etsy.com")},
    {".europa.eu", PROTO_EUROPA, MMT_STATICSTRING_LEN(".europa.eu")},
    {".eurosport.com", PROTO_EUROSPORT, MMT_STATICSTRING_LEN(".eurosport.com")},
    {".eurosport.fr", PROTO_EUROSPORT, MMT_STATICSTRING_LEN(".eurosport.fr")},
    {".eurosport.ru", PROTO_EUROSPORT, MMT_STATICSTRING_LEN(".eurosport.ru")},
    {".eurosport.se", PROTO_EUROSPORT, MMT_STATICSTRING_LEN(".eurosport.se")},
    {".fc2.com", PROTO_FC2, MMT_STATICSTRING_LEN(".fc2.com")},
    {".feidian.com", PROTO_FEIDIAN, MMT_STATICSTRING_LEN(".feidian.com")},
    {".fiverr.com", PROTO_FIVERR, MMT_STATICSTRING_LEN(".fiverr.com")},
    {".flickr.com", PROTO_FLICKR, MMT_STATICSTRING_LEN(".flickr.com")},
    {".staticflickr.com", PROTO_FLICKR, MMT_STATICSTRING_LEN(".staticflickr.com")},
    {".foxnews.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxnews.com")},
    {".foxsports.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsports.com")},
    {".foxsports.com.au", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsports.com.au")},
    {".foxsports.com.br", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsports.com.br")},
    {".foxsportsarizona.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsarizona.com")},
    {".foxsportsdetroit.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsdetroit.com")},
    {".foxsportsla.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsla.com")},
    {".foxsportsflorida.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsflorida.com")},
    {".foxsportsmidwest.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsmidwest.com")},
    {".foxsportsnext.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsnext.com")},
    {".foxsportsnorth.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsnorth.com")},
    {".foxsportsohio.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsohio.com")},
    {".foxsportsshop.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsshop.com")},
    {".foxsportssouth.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportssouth.com")},
    {".foxsportssouthwest.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportssouthwest.com")},
    {".foxsportstennessee.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportstennessee.com")},
    {".foxsportswest.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportswest.com")},
    {".foxsportswisconsin.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportswisconsin.com")},
    {".foxsportsradio.com", PROTO_FOX, MMT_STATICSTRING_LEN(".foxsportsradio.com")},
    {".free.fr", PROTO_FREE, MMT_STATICSTRING_LEN(".free.fr")},
    {".gamefaqs.com", PROTO_GAMEFAQS, MMT_STATICSTRING_LEN(".gamefaqs.com")},
    {".gamespot.com", PROTO_GAMESPOT, MMT_STATICSTRING_LEN(".gamespot.com")},
    {".gamespot.com.cn", PROTO_GAMESPOT, MMT_STATICSTRING_LEN(".gamespot.com.cn")},
    {".gap.com", PROTO_GAP, MMT_STATICSTRING_LEN(".gap.com")},
    {".garanti.com.tr", PROTO_GARANTI, MMT_STATICSTRING_LEN(".garanti.com.tr")},
    {".gazetevatanemek.com", PROTO_GAZETEVATAN, MMT_STATICSTRING_LEN(".gazetevatanemek.com")},
    {".vatanim.com.tr", PROTO_GAZETEVATAN, MMT_STATICSTRING_LEN(".vatanim.com.tr")},
    {".gigapeta.com", PROTO_GIGAPETA, MMT_STATICSTRING_LEN(".gigapeta.com")},
    {".github.com", PROTO_GITHUB, MMT_STATICSTRING_LEN(".github.com")},
    {".gittigidiyor.com", PROTO_GITTIGIDIYOR, MMT_STATICSTRING_LEN(".gittigidiyor.com")},
    {".globo.com", PROTO_GLOBO, MMT_STATICSTRING_LEN(".globo.com")},
    {".gnutellaforums.com", PROTO_GNUTELLA, MMT_STATICSTRING_LEN(".gnutellaforums.com")},
    {".go.com", PROTO_GO, MMT_STATICSTRING_LEN(".go.com")},
    {".godaddy.com", PROTO_GODADDY, MMT_STATICSTRING_LEN(".godaddy.com")},
    {".goo.ne.jp", PROTO_GOO, MMT_STATICSTRING_LEN(".goo.ne.jp")},
    {".grooveshark.com", PROTO_GROOVESHARK, MMT_STATICSTRING_LEN(".grooveshark.com")},
    {".groupon.com", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.com")},
    {".groupon.it", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.it")},
    {".groupon.de", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.de")},
    {".groupon.com.br", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.com.br")},
    {".groupon.co.uk", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.co.uk")},
    {".groupon.fr", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.fr")},
    {".groupon.cn", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.cn")},
    {".groupon.pl", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.pl")},
    {".groupon.es", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.es")},
    {".groupon.ru", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.ru")},
    {".groupon.jp", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.jp")},
    {".groupon.co.za", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.co.za")},
    {".groupon.my", PROTO_GROUPON, MMT_STATICSTRING_LEN(".groupon.my")},
    {".guardian.co.uk", PROTO_GUARDIAN, MMT_STATICSTRING_LEN(".guardian.co.uk")},
    {".guildwars2.com", PROTO_GUILDWARS, MMT_STATICSTRING_LEN(".guildwars2.com")},
    {".haberturk.com", PROTO_HABERTURK, MMT_STATICSTRING_LEN(".haberturk.com")},
    {".hao123.com", PROTO_HAO123, MMT_STATICSTRING_LEN(".hao123.com")},
    {".hepsiburada.com", PROTO_HEPSIBURADA, MMT_STATICSTRING_LEN(".hepsiburada.com")},
    {".hi5.com", PROTO_HI5, MMT_STATICSTRING_LEN(".hi5.com")},
    {".homedepot.com", PROTO_HOMEDEPOT, MMT_STATICSTRING_LEN(".homedepot.com")},
    {".hootsuite.com", PROTO_HOOTSUITE, MMT_STATICSTRING_LEN(".hootsuite.com")},
    {".hotmail.com", PROTO_HOTMAIL, MMT_STATICSTRING_LEN(".hotmail.com")},
    {".huffingtonpost.com", PROTO_HUFFINGTON_POST, MMT_STATICSTRING_LEN(".huffingtonpost.com")},
    {".hurriyet.com.tr", PROTO_HURRIYET, MMT_STATICSTRING_LEN(".hurriyet.com.tr")},
    {".hurpass.com", PROTO_HURRIYET, MMT_STATICSTRING_LEN(".hurpass.com")},
    {".icecast.org", PROTO_ICECAST, MMT_STATICSTRING_LEN(".icecast.org")},
    {".icloud.com", PROTO_APPLE_ICLOUD, MMT_STATICSTRING_LEN(".icloud.com")},
    {".ifeng.com", PROTO_IFENG, MMT_STATICSTRING_LEN(".ifeng.com")},
    {".ign.com", PROTO_IGN, MMT_STATICSTRING_LEN(".ign.com")},
    {".ikea.com", PROTO_IKEA, MMT_STATICSTRING_LEN(".ikea.com")},
    {".imdb.com", PROTO_INTERNET_MOVIE_DATABASE, MMT_STATICSTRING_LEN(".imdb.com")},
    {".imdb.es", PROTO_INTERNET_MOVIE_DATABASE, MMT_STATICSTRING_LEN(".imdb.es")},
    {".media-imdb.com", PROTO_INTERNET_MOVIE_DATABASE, MMT_STATICSTRING_LEN(".media-imdb.com")},
    {".imesh.com", PROTO_IMESH, MMT_STATICSTRING_LEN(".imesh.com")},
    {".imgur.com", PROTO_IMGUR, MMT_STATICSTRING_LEN(".imgur.com")},
    {".incredibar.com", PROTO_INCREDIBAR, MMT_STATICSTRING_LEN(".incredibar.com")},
    {".indiatimes.com", PROTO_INDIATIMES, MMT_STATICSTRING_LEN(".indiatimes.com")},
    {".instagram.com", PROTO_INSTAGRAM, MMT_STATICSTRING_LEN(".instagram.com")},
    {".irs.gov", PROTO_IRS, MMT_STATICSTRING_LEN(".irs.gov")},
    {".itunes.com", PROTO_APPLE_ITUNES, MMT_STATICSTRING_LEN(".itunes.com")},
    {".itunesapp.tk", PROTO_APPLE_ITUNES, MMT_STATICSTRING_LEN(".itunesapp.tk")},
    {".jabber.org", PROTO_UNENCRYPED_JABBER, MMT_STATICSTRING_LEN(".jabber.org")},
    {".japanpost.jp", PROTO_JAPANPOST, MMT_STATICSTRING_LEN(".japanpost.jp")},
    {".kakao.com", PROTO_KAKAO, MMT_STATICSTRING_LEN(".kakao.com")},
    {".kat.ph", PROTO_KAT, MMT_STATICSTRING_LEN(".kat.ph")},
    {".kazaa.com", PROTO_KAZAA, MMT_STATICSTRING_LEN(".kazaa.com")},
    {".midasplayer.com", PROTO_KING, MMT_STATICSTRING_LEN(".midasplayer.com")},
    {".king.com", PROTO_KING, MMT_STATICSTRING_LEN(".king.com")},
    {".kohls.com", PROTO_KOHLS, MMT_STATICSTRING_LEN(".kohls.com")},
    {".kongregate.com", PROTO_KONGREGATE, MMT_STATICSTRING_LEN(".kongregate.com")},
    {".kontiki.rs", PROTO_KONTIKI, MMT_STATICSTRING_LEN(".kontiki.rs")},
    {".lastfm.de", PROTO_LASTFM, MMT_STATICSTRING_LEN(".lastfm.de")},
    {".last.fm", PROTO_LASTFM, MMT_STATICSTRING_LEN(".last.fm")},
    {".leagueoflegends.com", PROTO_LEAGUEOFLEGENDS, MMT_STATICSTRING_LEN(".leagueoflegends.com")},
    {".legacy.com", PROTO_LEGACY, MMT_STATICSTRING_LEN(".legacy.com")},
    {".letv.com", PROTO_LETV, MMT_STATICSTRING_LEN(".letv.com")},
    {".livedoor.com", PROTO_LIVEDOOR, MMT_STATICSTRING_LEN(".livedoor.com")},
    {".liveinternet.ru", PROTO_LIVEINTERNET, MMT_STATICSTRING_LEN(".liveinternet.ru")},
    {".livejasmin.com", PROTO_LIVEJASMIN, MMT_STATICSTRING_LEN(".livejasmin.com")},
    {".livejournal.com", PROTO_LIVEJOURNAL, MMT_STATICSTRING_LEN(".livejournal.com")},
    {".livescore.com", PROTO_LIVESCORE, MMT_STATICSTRING_LEN(".livescore.com")},
    {".livingsocial.com", PROTO_LIVINGSOCIAL, MMT_STATICSTRING_LEN(".livingsocial.com")},
    {".lowes.com", PROTO_LOWES, MMT_STATICSTRING_LEN(".lowes.com")},
    {".macys.com", PROTO_MACYS, MMT_STATICSTRING_LEN(".macys.com")},
    {".mail.ru", PROTO_MAIL_RU, MMT_STATICSTRING_LEN(".mail.ru")},
    {".maplestory.pe.kr", PROTO_MAPLESTORY, MMT_STATICSTRING_LEN(".maplestory.pe.kr")},
    {".maplestorylife.com", PROTO_MAPLESTORY, MMT_STATICSTRING_LEN(".maplestorylife.com")},
    {".match.com", PROTO_MATCH, MMT_STATICSTRING_LEN(".match.com")},
    {".meebo.com", PROTO_MEEBO, MMT_STATICSTRING_LEN(".meebo.com")},
    {".windowslive.com", PROTO_WINDOWSLIVE, MMT_STATICSTRING_LEN(".windowslive.com")},
    {".windowslive.cn", PROTO_WINDOWSLIVE, MMT_STATICSTRING_LEN(".windowslive.cn")},
    {".update.microsoft.com", PROTO_WINUPDATE, MMT_STATICSTRING_LEN(".update.microsoft.com")},
    {".windowsupdatesonline.com", PROTO_WINUPDATE, MMT_STATICSTRING_LEN(".windowsupdatesonline.com")},
    {".windowsupdate.com", PROTO_WINUPDATE, MMT_STATICSTRING_LEN(".windowsupdate.com")},
    {".microsoft.com", PROTO_MICROSOFT, MMT_STATICSTRING_LEN(".microsoft.com")},
    {".windows.com", PROTO_MICROSOFT, MMT_STATICSTRING_LEN(".windows.com")},
    {".windows.net", PROTO_MICROSOFT, MMT_STATICSTRING_LEN(".windows.net")},
    {".milliyet.com.tr", PROTO_MILLIYET, MMT_STATICSTRING_LEN(".milliyet.com.tr")},
    {".minecraft.net", PROTO_MINECRAFT, MMT_STATICSTRING_LEN(".minecraft.net")},
    {".minecraftwiki.net", PROTO_MINECRAFT, MMT_STATICSTRING_LEN(".minecraftwiki.net")},
    {".miniclip.com", PROTO_MINICLIP, MMT_STATICSTRING_LEN(".miniclip.com")},
    {".mlb.com", PROTO_MLBASEBALL, MMT_STATICSTRING_LEN(".mlb.com")},
    {".mmo-champion.com", PROTO_MMO_CHAMPION, MMT_STATICSTRING_LEN(".mmo-champion.com")},
    {".mms.com", PROTO_MMS, MMT_STATICSTRING_LEN(".mms.com")},
    {".mozilla.org", PROTO_MOZILLA, MMT_STATICSTRING_LEN(".mozilla.org")},
    {".multiply.com", PROTO_MULTIPLY, MMT_STATICSTRING_LEN(".multiply.com")},
    {".mynet.com", PROTO_MYNET, MMT_STATICSTRING_LEN(".mynet.com")},
    {".myspace.com", PROTO_MYSPACE, MMT_STATICSTRING_LEN(".myspace.com")},
    {".mywebsearch.com", PROTO_MYWEBSEARCH, MMT_STATICSTRING_LEN(".mywebsearch.com")},
    {".nba.com", PROTO_NBA, MMT_STATICSTRING_LEN(".nba.com")},
    {".neobux.com", PROTO_NEOBUX, MMT_STATICSTRING_LEN(".neobux.com")},
    {".netflix.com", PROTO_NETFLIX, MMT_STATICSTRING_LEN(".netflix.com")},
    {".newegg.com", PROTO_NEWEGG, MMT_STATICSTRING_LEN(".newegg.com")},
    {".newsmax.com", PROTO_NEWSMAX, MMT_STATICSTRING_LEN(".newsmax.com")},
    {".nfl.com", PROTO_NFL, MMT_STATICSTRING_LEN(".nfl.com")},
    {".nicovideo.jp", PROTO_NICOVIDEO, MMT_STATICSTRING_LEN(".nicovideo.jp")},
    {".nih.gov", PROTO_NIH, MMT_STATICSTRING_LEN(".nih.gov")},
    {".nordstrom.com", PROTO_NORDSTROM, MMT_STATICSTRING_LEN(".nordstrom.com")},
    {".nytimes.com", PROTO_NYTIMES, MMT_STATICSTRING_LEN(".nytimes.com")},
    {".odnoklassniki.ru", PROTO_ODNOKLASSNIKI, MMT_STATICSTRING_LEN(".odnoklassniki.ru")},
    {".onet.pl", PROTO_ONET, MMT_STATICSTRING_LEN(".onet.pl")},
    {".orangedonkey.net", PROTO_ORANGEDONKEY, MMT_STATICSTRING_LEN(".orangedonkey.net")},
    {".outbrain.com", PROTO_OUTBRAIN, MMT_STATICSTRING_LEN(".outbrain.com")},
    {".overstock.com", PROTO_OVERSTOCK, MMT_STATICSTRING_LEN(".overstock.com")},
    {".paypal.com", PROTO_PAYPAL, MMT_STATICSTRING_LEN(".paypal.com")},
    {".pch.com", PROTO_PCH, MMT_STATICSTRING_LEN(".pch.com")},
    {".pconline.com.cn", PROTO_PCONLINE, MMT_STATICSTRING_LEN(".pconline.com.cn")},
    {".photobucket.com", PROTO_PHOTOBUCKET, MMT_STATICSTRING_LEN(".photobucket.com")},
    {".pinterest.com", PROTO_PINTEREST, MMT_STATICSTRING_LEN(".pinterest.com")},
    {".playstation.com", PROTO_PLAYSTATION, MMT_STATICSTRING_LEN(".playstation.com")},
    {".absolute-playstation.com", PROTO_PLAYSTATION, MMT_STATICSTRING_LEN(".absolute-playstation.com")},
    {".planetplaystation.com", PROTO_PLAYSTATION, MMT_STATICSTRING_LEN(".planetplaystation.com")},
    {".playstationnetwork.com", PROTO_PLAYSTATION, MMT_STATICSTRING_LEN(".playstationnetwork.com")},
    {".pogo.com", PROTO_POGO, MMT_STATICSTRING_LEN(".pogo.com")},
    {".pornhub.com", PROTO_PORNHUB, MMT_STATICSTRING_LEN(".pornhub.com")},
    {".pplive.cn", PROTO_PPLIVE, MMT_STATICSTRING_LEN(".pplive.cn")},
    {".ppstream.com", PROTO_PPSTREAM, MMT_STATICSTRING_LEN(".ppstream.com")},
    {".premierleague.com", PROTO_PREMIERLEAGUE, MMT_STATICSTRING_LEN(".premierleague.com")},
    {".qq.com", PROTO_QQ, MMT_STATICSTRING_LEN(".qq.com")},
    {".qqlive.com", PROTO_QQLIVE, MMT_STATICSTRING_LEN(".qqlive.com")},
    {".r10.net", PROTO_R10, MMT_STATICSTRING_LEN(".r10.net")},
    {".rakuten.co.jp", PROTO_RAKUTEN, MMT_STATICSTRING_LEN(".rakuten.co.jp")},
    {".reddit.com", PROTO_REDDIT, MMT_STATICSTRING_LEN(".reddit.com")},
    {".redtube.com", PROTO_REDTUBE, MMT_STATICSTRING_LEN(".redtube.com")},
    {".redtubefiles.com", PROTO_REDTUBE, MMT_STATICSTRING_LEN(".redtubefiles.com")},
    {".reference.com", PROTO_REFERENCE, MMT_STATICSTRING_LEN(".reference.com")},
    {".renren.com", PROTO_RENREN, MMT_STATICSTRING_LEN(".renren.com")},
    {".roblox.com", PROTO_ROBLOX, MMT_STATICSTRING_LEN(".roblox.com")},
    {".rovio.com", PROTO_ROVIO, MMT_STATICSTRING_LEN(".rovio.com")},
    {".sabah.com.tr", PROTO_SABAHTR, MMT_STATICSTRING_LEN(".sabah.com.tr")},
    {".sahibinden.com", PROTO_SAHIBINDEN, MMT_STATICSTRING_LEN(".sahibinden.com")},
    {".salesforce.com", PROTO_SALESFORCE, MMT_STATICSTRING_LEN(".salesforce.com")},
    {".salon.com", PROTO_SALON, MMT_STATICSTRING_LEN(".salon.com")},
    {".searchnu.com", PROTO_SEARCHNU, MMT_STATICSTRING_LEN(".searchnu.com")},
    {".search-results.com", PROTO_SEARCH_RESULTS, MMT_STATICSTRING_LEN(".search-results.com")},
    {".sears.com", PROTO_SEARS, MMT_STATICSTRING_LEN(".sears.com")},
    {".secondlife.com", PROTO_SECONDLIFE, MMT_STATICSTRING_LEN(".secondlife.com")},
    {".secureserver.net", PROTO_SECURESERVER, MMT_STATICSTRING_LEN(".secureserver.net")},
    {".shoutcast.com", PROTO_SHOUTCAST, MMT_STATICSTRING_LEN(".shoutcast.com")},

    {".shazamid.com", PROTO_SHAZAM, MMT_STATICSTRING_LEN(".shazamid.com")},
    {".shazam.com", PROTO_SHAZAM, MMT_STATICSTRING_LEN(".shazam.com")},

    {".video.sina.com.cn", PROTO_SINA, MMT_STATICSTRING_LEN(".video.sina.com.cn")},
    {".sina.com.cn", PROTO_SINA, MMT_STATICSTRING_LEN(".sina.com.cn")},
    {".siteadvisor.com", PROTO_SITEADVISOR, MMT_STATICSTRING_LEN(".siteadvisor.com")},
    {".sky.com", PROTO_SKY, MMT_STATICSTRING_LEN(".sky.com")},
    {".skype.com", PROTO_SKYPE, MMT_STATICSTRING_LEN(".skype.com")},
    { ".skype.",PROTO_SKYPE, MMT_STATICSTRING_LEN(".skype.") },
    { ".skypeassets.",PROTO_SKYPE, MMT_STATICSTRING_LEN(".skypeassets.") },
    { ".skypedata.", PROTO_SKYPE, MMT_STATICSTRING_LEN(".skypedata.") },
    { ".skypeecs-",PROTO_SKYPE, MMT_STATICSTRING_LEN(".skypeecs-") },
    { ".skypeforbusiness.",PROTO_SKYPE, MMT_STATICSTRING_LEN(".skypeforbusiness.") },
    { ".lync.com",PROTO_SKYPE, MMT_STATICSTRING_LEN(".lync.com") },
    {".skyrock.com", PROTO_SKYROCK, MMT_STATICSTRING_LEN(".skyrock.com")},
    {".skysports.com", PROTO_SKYSPORTS, MMT_STATICSTRING_LEN(".skysports.com")},
    {".slate.com", PROTO_SLATE, MMT_STATICSTRING_LEN(".slate.com")},
    {".slideshare.net", PROTO_SLIDESHARE, MMT_STATICSTRING_LEN(".slideshare.net")},
    {".softonic.com", PROTO_SOFTONIC, MMT_STATICSTRING_LEN(".softonic.com")},
    {".sogou.com", PROTO_SOGOU, MMT_STATICSTRING_LEN(".sogou.com")},
    {".sohu.com", PROTO_SOHU, MMT_STATICSTRING_LEN(".sohu.com")},
    {".sopcast.com", PROTO_SOPCAST, MMT_STATICSTRING_LEN(".sopcast.com")},
    {".soso.com", PROTO_SOSO, MMT_STATICSTRING_LEN(".soso.com")},
    {".soulseekqt.net", PROTO_SOULSEEK, MMT_STATICSTRING_LEN(".soulseekqt.net")},
    {".soundcloud.com", PROTO_SOUNDCLOUD, MMT_STATICSTRING_LEN(".soundcloud.com")},
    {".sourceforge.net", PROTO_SOURGEFORGE, MMT_STATICSTRING_LEN(".sourceforge.net")},
    {".spiegel.de", PROTO_SPIEGEL, MMT_STATICSTRING_LEN(".spiegel.de")},
    {".sporx.com", PROTO_SPORX, MMT_STATICSTRING_LEN(".sporx.com")},
    {".spotify.com", PROTO_SPOTIFY, MMT_STATICSTRING_LEN(".spotify.com")},
    {".squidoo.com", PROTO_SQUIDOO, MMT_STATICSTRING_LEN(".squidoo.com")},
    {".stackoverflow.com", PROTO_STACK_OVERFLOW, MMT_STATICSTRING_LEN(".stackoverflow.com")},
    {".statcounter.com", PROTO_STATCOUNTER, MMT_STATICSTRING_LEN(".statcounter.com")},
    {".steamgames.com", PROTO_STEAM, MMT_STATICSTRING_LEN(".steamgames.com")},
    {".steampowered.com", PROTO_STEAM, MMT_STATICSTRING_LEN(".steampowered.com")},
    {".stumbleupon.com", PROTO_STUMBLEUPON, MMT_STATICSTRING_LEN(".stumbleupon.com")},
    {".sulekha.com", PROTO_SULEKHA, MMT_STATICSTRING_LEN(".sulekha.com")},
    {".tagged.com", PROTO_TAGGED, MMT_STATICSTRING_LEN(".tagged.com")},
    {".taobao.com", PROTO_TAOBAO, MMT_STATICSTRING_LEN(".taobao.com")},
    {".taobao.org", PROTO_TAOBAO, MMT_STATICSTRING_LEN(".taobao.org")},
    {".target.com", PROTO_TARGET, MMT_STATICSTRING_LEN(".target.com")},
    {".t.co", PROTO_TCO, MMT_STATICSTRING_LEN(".t.co")},
    {".themeforest.net", PROTO_THEMEFOREST, MMT_STATICSTRING_LEN(".themeforest.net")},
    {".thepiratebay.se", PROTO_THE_PIRATE_BAY, MMT_STATICSTRING_LEN(".thepiratebay.se")},
    {".tianya.cn", PROTO_TIANYA, MMT_STATICSTRING_LEN(".tianya.cn")},
    {".tmall.com", PROTO_TMALL, MMT_STATICSTRING_LEN(".tmall.com")},
    {".torrentz.eu", PROTO_TORRENTZ, MMT_STATICSTRING_LEN(".torrentz.eu")},
    {".truphone.com", PROTO_TRUPHONE, MMT_STATICSTRING_LEN(".truphone.com")},
    {".tube8.com", PROTO_TUBE8, MMT_STATICSTRING_LEN(".tube8.com")},
    {".tudou.com", PROTO_TUDOU, MMT_STATICSTRING_LEN(".tudou.com")},
    {".tuenti.com", PROTO_TUENTI, MMT_STATICSTRING_LEN(".tuenti.com")},
    {".tumblr.com", PROTO_TUMBLR, MMT_STATICSTRING_LEN(".tumblr.com")},
    {".tvants.fr", PROTO_TVANTS, MMT_STATICSTRING_LEN(".tvants.fr")},
    {".ustream.tv", PROTO_USTREAM, MMT_STATICSTRING_LEN(".ustream.tv")},
    {".ubi.com", PROTO_UBI, MMT_STATICSTRING_LEN(".ubi.com")},
    {".ucoz.ru", PROTO_UCOZ, MMT_STATICSTRING_LEN(".ucoz.ru")},
    {".uol.com.br", PROTO_UOL, MMT_STATICSTRING_LEN(".uol.com.br")},
    {".state.gov", PROTO_USDEPARTMENTOFSTATE, MMT_STATICSTRING_LEN(".state.gov")},
    {".veohtv.co", PROTO_HTTP_APPLICATION_VEOHTV, MMT_STATICSTRING_LEN(".veohtv.co")},
    {".viadeo.com", PROTO_VIADEO, MMT_STATICSTRING_LEN(".viadeo.com")},
    {".viber.com", PROTO_VIBER, MMT_STATICSTRING_LEN(".viber.com")},
    {".cdn.viber.com", PROTO_VIBER, MMT_STATICSTRING_LEN(".viber.com")},
    {".vimeo.com", PROTO_VIMEO, MMT_STATICSTRING_LEN(".vimeo.com")},
    {".vimeocdn.com", PROTO_VIMEO, MMT_STATICSTRING_LEN(".vimeocdn.com")},
    {".vk.com", PROTO_VK, MMT_STATICSTRING_LEN(".vk.com")},
    {".vkontakte.ru", PROTO_VKONTAKTE, MMT_STATICSTRING_LEN(".vkontakte.ru")},
    {".walmart.com", PROTO_WALMART, MMT_STATICSTRING_LEN(".walmart.com")},
    {".warriorforum.com", PROTO_WARRIORFORUM, MMT_STATICSTRING_LEN(".warriorforum.com")},
    {".wayn.com", PROTO_WAYN, MMT_STATICSTRING_LEN(".wayn.com")},
    {".weather.com", PROTO_WEATHER, MMT_STATICSTRING_LEN(".weather.com")},
    {".webex.com", PROTO_WEBEX, MMT_STATICSTRING_LEN(".webex.com")},
    {".weeklystandard.com", PROTO_WEEKLYSTANDARD, MMT_STATICSTRING_LEN(".weeklystandard.com")},
    {".weibo.com", PROTO_WEIBO, MMT_STATICSTRING_LEN(".weibo.com")},
    {".wellsfargo.com", PROTO_WELLSFARGO, MMT_STATICSTRING_LEN(".wellsfargo.com")},
    {".whatsapp.com", PROTO_WHATSAPP, MMT_STATICSTRING_LEN(".whatsapp.com")},
    {".whatsapp.net", PROTO_WHATSAPP, MMT_STATICSTRING_LEN(".whatsapp.net")},
    {".wigetmedia.com", PROTO_WIGETMEDIA, MMT_STATICSTRING_LEN(".wigetmedia.com")},
    {".wikia.com", PROTO_WIKIA, MMT_STATICSTRING_LEN(".wikia.com")},
    {".wikimedia.org", PROTO_WIKIMEDIA, MMT_STATICSTRING_LEN(".wikimedia.org")},
    {".williamhill.com", PROTO_WILLIAMHILL, MMT_STATICSTRING_LEN(".williamhill.com")},
    {".wordpress.com", PROTO_WORDPRESS_ORG, MMT_STATICSTRING_LEN(".wordpress.com")},
    {".wordpress.org", PROTO_WORDPRESS_ORG, MMT_STATICSTRING_LEN(".wordpress.org")},
    {".warcraft.org", PROTO_WORLDOFWARCRAFT, MMT_STATICSTRING_LEN(".warcraft.org")},
    {".worldofwarcraft.co.kr", PROTO_WORLDOFWARCRAFT, MMT_STATICSTRING_LEN(".worldofwarcraft.co.kr")},
    {".wowhead.com", PROTO_WOWHEAD, MMT_STATICSTRING_LEN(".wowhead.com")},
    {".wwe.com", PROTO_WWE, MMT_STATICSTRING_LEN(".wwe.com")},
    {".xbox.com", PROTO_XBOX, MMT_STATICSTRING_LEN(".xbox.com")},
    {".xhamster.com", PROTO_XHAMSTER, MMT_STATICSTRING_LEN(".xhamster.com")},
    {".xing.com", PROTO_XING, MMT_STATICSTRING_LEN(".xing.com")},
    {".xinhuanet.com", PROTO_XINHUANET, MMT_STATICSTRING_LEN(".xinhuanet.com")},
    {".xnxx.com", PROTO_XNXX, MMT_STATICSTRING_LEN(".xnxx.com")},
    {".xvideos.com", PROTO_XVIDEOS, MMT_STATICSTRING_LEN(".xvideos.com")},
    {".yandex.ru", PROTO_YANDEX, MMT_STATICSTRING_LEN(".yandex.ru")},
    {".yandex.com.tr", PROTO_YANDEX, MMT_STATICSTRING_LEN(".yandex.com.tr")},
    {".yandex.com", PROTO_YANDEX, MMT_STATICSTRING_LEN(".yandex.com")},
    {".yelp.com", PROTO_YELP, MMT_STATICSTRING_LEN(".yelp.com")},
    {".youku.com", PROTO_YOUKU, MMT_STATICSTRING_LEN(".youku.com")},
    {".youporn.com", PROTO_YOUPORN, MMT_STATICSTRING_LEN(".youporn.com")},
    {".zappos.com", PROTO_ZAPPOS, MMT_STATICSTRING_LEN(".zappos.com")},
    {".zattoo.com", PROTO_ZATTOO, MMT_STATICSTRING_LEN(".zattoo.com")},
    {".zedo.com", PROTO_ZEDO, MMT_STATICSTRING_LEN(".zedo.com")},
    {".zol.com.cn", PROTO_ZOL, MMT_STATICSTRING_LEN(".zol.com.cn")},
    {".zynga.com", PROTO_ZYNGA, MMT_STATICSTRING_LEN(".zynga.com")},
    {".zynga.co.jp", PROTO_ZYNGA, MMT_STATICSTRING_LEN(".zynga.co.jp")},
    {".zynga.org", PROTO_ZYNGA, MMT_STATICSTRING_LEN(".zynga.org")},
    {".zynga.tm", PROTO_ZYNGA, MMT_STATICSTRING_LEN(".zynga.tm")},
    {".zyngawithfriends.com", PROTO_ZYNGA, MMT_STATICSTRING_LEN(".zyngawithfriends.com")},
    {".buzznet.com", PROTO_BUZZNET, MMT_STATICSTRING_LEN(".buzznet.com")},
    {".comedy.com", PROTO_COMEDY, MMT_STATICSTRING_LEN(".comedy.com")},
    {".rambler.ru", PROTO_RAMBLER, MMT_STATICSTRING_LEN(".rambler.ru")},
    {".smugmug.com", PROTO_SMUGMUG, MMT_STATICSTRING_LEN(".smugmug.com")},
    {".archive.org", PROTO_ARCHIEVE, MMT_STATICSTRING_LEN(".archive.org")},
    {".cityline.ca", PROTO_CITYNEWS, MMT_STATICSTRING_LEN(".cityline.ca")},
    {".citynews.ca", PROTO_CITYNEWS, MMT_STATICSTRING_LEN(".citynews.ca")},
    {".sciencestage.com", PROTO_SCIENCESTAGE, MMT_STATICSTRING_LEN(".sciencestage.com")},
    {".oneworldgroup.org", PROTO_ONEWORLD, MMT_STATICSTRING_LEN(".oneworldgroup.org")},
    {".oneworld.net", PROTO_ONEWORLD, MMT_STATICSTRING_LEN(".oneworld.net")},
    {".oneworld.org", PROTO_ONEWORLD, MMT_STATICSTRING_LEN(".oneworld.org")},
    {".disqus.com", PROTO_DISQUS, MMT_STATICSTRING_LEN(".disqus.com")},
    {".blogcu.com", PROTO_BLOGCU, MMT_STATICSTRING_LEN(".blogcu.com")},
    {".ekolay.net", PROTO_EKOLEY, MMT_STATICSTRING_LEN(".ekolay.net")},
    {".e-kolay.net", PROTO_EKOLEY, MMT_STATICSTRING_LEN(".e-kolay.net")},
    {".500px.net", PROTO_500PX, MMT_STATICSTRING_LEN(".500px.net")},
    {".500px.com", PROTO_500PX, MMT_STATICSTRING_LEN(".500px.com")},
    {".fotki.com", PROTO_FOTKI, MMT_STATICSTRING_LEN(".fotki.com")},
    {".fotolog.com", PROTO_FOTOLOG, MMT_STATICSTRING_LEN(".fotolog.com")},
    {".jalbum.net", PROTO_JALBUM, MMT_STATICSTRING_LEN(".jalbum.net")},
    {".lockerz.com", PROTO_LOCKERZ, MMT_STATICSTRING_LEN(".lockerz.com")},
    {".panoramio.com", PROTO_PANORAMIO, MMT_STATICSTRING_LEN(".panoramio.com")},
    {".snapfish.fr", PROTO_SNAPFISH, MMT_STATICSTRING_LEN(".snapfish.fr")},
    {".snapfish.com", PROTO_SNAPFISH, MMT_STATICSTRING_LEN(".snapfish.com")},
    {".sf-cdn.com", PROTO_SNAPFISH, MMT_STATICSTRING_LEN(".sf-cdn.com")},
    {".webshots.com", PROTO_WEBSHOTS, MMT_STATICSTRING_LEN(".webshots.com")},
    {".mega.co.nz", PROTO_MEGA, MMT_STATICSTRING_LEN(".mega.co.nz")},
    {".mega.cl", PROTO_MEGA, MMT_STATICSTRING_LEN(".mega.cl")},
    {".vidoosh.tv", PROTO_VIDOOSH, MMT_STATICSTRING_LEN(".vidoosh.tv")},
    {".afreeca.com", PROTO_AFREECA, MMT_STATICSTRING_LEN(".afreeca.com")},
    {".afreecatv.com", PROTO_AFREECA, MMT_STATICSTRING_LEN(".afreecatv.com")},
    {".afreeca.tv", PROTO_AFREECA, MMT_STATICSTRING_LEN(".afreeca.tv")},
    {".afreeca.co.kr", PROTO_AFREECA, MMT_STATICSTRING_LEN(".afreeca.co.kr")},
    {".afreeca.com:8079", PROTO_AFREECA, MMT_STATICSTRING_LEN(".afreeca.com:8079")},
    {".wildscreen.tv", PROTO_WILDSCREEN, MMT_STATICSTRING_LEN(".wildscreen.tv")},
    {".blogtv.com", PROTO_BLOGTV, MMT_STATICSTRING_LEN(".blogtv.com")},
    {".hulu.com", PROTO_HULU, MMT_STATICSTRING_LEN(".hulu.com")},
    {".huluim.com", PROTO_HULU, MMT_STATICSTRING_LEN(".huluim.com")},
    {".mevio.com", PROTO_MEVIO, MMT_STATICSTRING_LEN(".mevio.com")},
    {".meviodisplayads.com", PROTO_MEVIO, MMT_STATICSTRING_LEN(".meviodisplayads.com")},
    {".livestream.com", PROTO_LIVESTREAM, MMT_STATICSTRING_LEN(".livestream.com")},
    {".liveleak.com", PROTO_LIVELEAK, MMT_STATICSTRING_LEN(".liveleak.com")},
    {".deezer.com", PROTO_DEEZER, MMT_STATICSTRING_LEN(".deezer.com")},
    {".blip.tv", PROTO_BLIPTV, MMT_STATICSTRING_LEN(".blip.tv")},
    {".break.com", PROTO_BREAK, MMT_STATICSTRING_LEN(".break.com")},
    {".brkmd.com", PROTO_BREAK, MMT_STATICSTRING_LEN(".brkmd.com")},
    {".breakmedia.com", PROTO_BREAK, MMT_STATICSTRING_LEN(".breakmedia.com")},
    {".citytv.com", PROTO_CITYTV, MMT_STATICSTRING_LEN(".citytv.com")},
    {".comedycentral.com", PROTO_COMEDYCENTRAL, MMT_STATICSTRING_LEN(".comedycentral.com")},
    {".engagemedia.org", PROTO_ENGAGEMEDIA, MMT_STATICSTRING_LEN(".engagemedia.org")},
    {".ifilm.com", PROTO_SCREENJUNKIES, MMT_STATICSTRING_LEN(".ifilm.com")},
    {".screenjunkies.com", PROTO_SCREENJUNKIES, MMT_STATICSTRING_LEN(".screenjunkies.com")},
    {".rutube.ru", PROTO_RUTUBE, MMT_STATICSTRING_LEN(".rutube.ru")},
    {".sevenload.com", PROTO_SEVENLOAD, MMT_STATICSTRING_LEN(".sevenload.com")},
    {".sevenload.net", PROTO_SEVENLOAD, MMT_STATICSTRING_LEN(".sevenload.net")},
    {".mubi.com", PROTO_MUBI, MMT_STATICSTRING_LEN(".mubi.com")},
    {".izlesene.com", PROTO_IZLESENE, MMT_STATICSTRING_LEN(".izlesene.com")},
    {".imgiz.com", PROTO_IZLESENE, MMT_STATICSTRING_LEN(".imgiz.com"), MMT_CONTENT_IMAGE},
    {".box.com", PROTO_BOX, MMT_STATICSTRING_LEN(".box.com")},
    {".7static.com", PROTO_7DIGITAL, MMT_STATICSTRING_LEN(".7static.com")},
    {".7digital.com", PROTO_7DIGITAL, MMT_STATICSTRING_LEN(".7digital.com")},

    {".watchfreeinhd.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".watchfreeinhd.com")},
    {".played.to", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".played.to")},
    {".vureel.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".vureel.com")},
    {".reelhd.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".reelhd.com")},
    {".itshd.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".itshd.com")},
    {".filmlush.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".filmlush.com")},
    {".nowvideo.eu", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".nowvideo.eu")},
    {".primeshare.tv", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".primeshare.tv")},
    {".flashx.tv", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".flashx.tv")},
    {".ilivid.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".ilivid.com")},
    {".gorillavid.in", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".gorillavid.in")},
    {".youwatch.org", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".youwatch.org")},
    {".watchfreemovies.ch", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".watchfreemovies.ch")},
    {".novamov.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".novamov.com")},
    {".vidstream.in", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".vidstream.in")},
    {".filmlinks4u.net", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".filmlinks4u.net")},
    {".videozed.net", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".videozed.net")},
    {".videoweed.es", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".videoweed.es")},
    {".videoweed.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".videoweed.com")},
    {".faststream.in", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".faststream.in")},
    {".flixster.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".flixster.com")},
    {".1channel.ch", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".1channel.ch")},
    {".donevideo.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".donevideo.com")},
    {".movie2k.to", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".movie2k.to")},
    {".stream2k.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".stream2k.com")},
    {".qik.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".qik.com")},
    {".veervid.com", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".veervid.com")},
    {".tv-tube.tv", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".tv-tube.tv")},
    {".fleon.me", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".fleon.me")},
    {".potlocker.net", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".potlocker.net")},
    {".myvideo.de", PROTO_VIDEO_HOSTING, MMT_STATICSTRING_LEN(".myvideo.de")},

    {".gameforge.com", PROTO_GAMEFORGE, MMT_STATICSTRING_LEN(".gameforge.com")},
    {".gameforge.de", PROTO_GAMEFORGE, MMT_STATICSTRING_LEN(".gameforge.de")},
    {".gameforgeads.de", PROTO_GAMEFORGE, MMT_STATICSTRING_LEN(".gameforgeads.de")},
    {".gamepay.de", PROTO_GAMEFORGE, MMT_STATICSTRING_LEN(".gamepay.de")},
    {".gfsrv.net", PROTO_GAMEFORGE, MMT_STATICSTRING_LEN(".gfsrv.net")},
    {".metin-2.com", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin-2.com")},
    {".metin-2.ru", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin-2.ru")},
    {".metin2-team.pl", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2-team.pl")},
    {".metin2.ae", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.ae")},
    {".metin2.co.uk", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.co.uk")},
    {".metin2.com.pt", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.com.pt")},
    {".metin2.cz", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.cz")},
    {".metin2.de", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.de")},
    {".metin2.dk", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.dk")},
    {".metin2.es", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.es")},
    {".metin2.fr", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.fr")},
    {".metin2.gr", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.gr")},
    {".metin2.hu", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.hu")},
    {".metin2.it", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.it")},
    {".metin2.nl", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.nl")},
    {".metin2.org", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.org")},
    {".metin2.pl", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.pl")},
    {".metin2.ro", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2.ro")},
    {".metin2wiki.de", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2wiki.de")},
    {".metin2wiki.eu", PROTO_METIN2, MMT_STATICSTRING_LEN(".metin2wiki.eu")},
    {".mmogame.com", PROTO_OGAME, MMT_STATICSTRING_LEN(".mmogame.com")},
    {".mmogame.de", PROTO_OGAME, MMT_STATICSTRING_LEN(".mmogame.de")},
    {".o-game.co.kr", PROTO_OGAME, MMT_STATICSTRING_LEN(".o-game.co.kr")},
    {".ogame.ba", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.ba")},
    {".ogame.cn.com", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.cn.com")},
    {".ogame.com.cn", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.com.cn")},
    {".ogame.com.es", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.com.es")},
    {".ogame.com.hr", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.com.hr")},
    {".ogame.com.pt", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.com.pt")},
    {".ogame.com.tr", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.com.tr")},
    {".ogame.com.tw", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.com.tw")},
    {".ogame.cz", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.cz")},
    {".ogame.de", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.de")},
    {".ogame.dk", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.dk")},
    {".ogame.es", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.es")},
    {".ogame.fr", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.fr")},
    {".ogame.gr", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.gr")},
    {".ogame.hu", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.hu")},
    {".ogame.it", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.it")},
    {".ogame.jp", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.jp")},
    {".ogame.lt", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.lt")},
    {".ogame.lv", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.lv")},
    {".ogame.nl", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.nl")},
    {".ogame.no", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.no")},
    {".ogame.org", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.org")},
    {".ogame.pl", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.pl")},
    {".ogame.ro", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.ro")},
    {".ogame.rs", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.rs")},
    {".ogame.ru", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.ru")},
    {".ogame.se", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.se")},
    {".ogame.si", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.si")},
    {".ogame.sk", PROTO_OGAME, MMT_STATICSTRING_LEN(".ogame.sk")},
    {".battle-knight.com", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battle-knight.com")},
    {".battle-knight.net", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battle-knight.net")},
    {".battle-knight.org", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battle-knight.org")},
    {".battleknight.cn", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.cn")},
    {".battleknight.co.il", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.co.il")},
    {".battleknight.co.uk", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.co.uk")},
    {".battleknight.com.cn", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.com.cn")},
    {".battleknight.com.mx", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.com.mx")},
    {".battleknight.com.pt", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.com.pt")},
    {".battleknight.com.ve", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.com.ve")},
    {".battleknight.cz", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.cz")},
    {".battleknight.de", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.de")},
    {".battleknight.dk", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.dk")},
    {".battleknight.es", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.es")},
    {".battleknight.fr", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.fr")},
    {".battleknight.gr", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.gr")},
    {".battleknight.hu", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.hu")},
    {".battleknight.it", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.it")},
    {".battleknight.lt", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.lt")},
    {".battleknight.nl", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.nl")},
    {".battleknight.no", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.no")},
    {".battleknight.pl", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.pl")},
    {".battleknight.ro", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.ro")},
    {".battleknight.ru", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.ru")},
    {".battleknight.se", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.se")},
    {".battleknight.sk", PROTO_BATTLEKNIGHT, MMT_STATICSTRING_LEN(".battleknight.sk")},
    {".4story.ae", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.ae")},
    {".4story.biz", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.biz")},
    {".4story.co.uk", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.co.uk")},
    {".4story.cz", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.cz")},
    {".4story.de", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.de")},
    {".4story.es", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.es")},
    {".4story.fr", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.fr")},
    {".4story.gr", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.gr")},
    {".4story.it", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.it")},
    {".4story.pl", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.pl")},
    {".4story.pt", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.pt")},
    {".4story.ro", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.ro")},
    {".4story.web.tr", PROTO_4STORY, MMT_STATICSTRING_LEN(".4story.web.tr")},

    {".tango.me", PROTO_TANGO, MMT_STATICSTRING_LEN(".tango.me")},
    {".tango.me:8080", PROTO_TANGO, MMT_STATICSTRING_LEN(".tango.me:8080")},
    {".line.naver.jp", PROTO_LINE, MMT_STATICSTRING_LEN(".line.naver.jp")},
    {".line.me", PROTO_LINE, MMT_STATICSTRING_LEN(".line.me")},

    // PROTO_DIRECT_DOWNLOAD_LINK
    {".mediafire.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".mediafire.com")},
    {".4shared.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".4shared.com")},
    {".depositfiles.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".depositfiles.com")},
    {".scribd.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".scribd.com")},
    {".rapidshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".rapidshare.com")},
    {".rapidshare.de", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".rapidshare.de")},
    {".rapidshare.ru", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".rapidshare.ru")},
    {".rapidshark.pl", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".rapidshark.pl")},
    {".uploaded.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploaded.net")},
    {".filestube.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filestube.com")},
    {".turbobit.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".turbobit.net")},
    {".letitbit.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".letitbit.net")},
    {".bitshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".bitshare.com")},
    {".hotfile.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hotfile.com")},
    {".freakshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".freakshare.com")},
    {".115.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".115.com")},
    {".extabit.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".extabit.com")},
    {".sendspace.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".sendspace.com")},
    {".ziddu.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".ziddu.com")},
    {".filepost.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filepost.com")},
    {".filepost.ru", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filepost.ru")},
    {".uploading.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploading.com")},
    {".uploading.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploading.to")},
    {".filefactory.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filefactory.com")},
    {".2shared.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".2shared.com")},
    {".netload.in", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".netload.in")},
    {".fileserve.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fileserve.com")},
    {".hulkshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hulkshare.com")},
    {".shareflare.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".shareflare.net")},
    {".crocko.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".crocko.com")},
    {".uloz.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uloz.to")},
    {".gamefront.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".gamefront.com")},
    {".share-online.biz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".share-online.biz")},
    {".jumbofiles.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".jumbofiles.com")},
    {".uptobox.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uptobox.com")},
    {".rusfolder.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".rusfolder.com")},
    {".megashares.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".megashares.com")},
    {".unibytes.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".unibytes.com")},
    {".filecloud.io", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filecloud.io")},
    {".vip-file.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".vip-file.com")},
    {".1fichier.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".1fichier.com")},
    {".filesflash.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filesflash.com")},
    {".filesend.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filesend.to")},
    {".uploadc.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploadc.com")},
    {".movreel.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".movreel.com")},
    {".uploadstation.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploadstation.com")},
    {".cramit.in", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".cramit.in")},
    {".filejungle.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filejungle.com")},
    {".filesmonster.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filesmonster.com")},
    {".adrive.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".adrive.com")},
    {".fileflyer.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fileflyer.com")},
    {".queenshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".queenshare.com")},
    {".gigasize.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".gigasize.com")},
    {".czshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".czshare.com")},
    {".fshare.vn", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fshare.vn")},
    {".4share.vn", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".4share.vn")},
    {".transferbigfiles.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".transferbigfiles.com")},
    {".easybytez.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".easybytez.com")},
    {".videobb.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".videobb.com")},
    {".hitfile.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hitfile.net")},
    {".filebase.ws", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filebase.ws")},
    {".filebase.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filebase.to")},
    {".vnn.vn", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".vnn.vn")},
    {".datei.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".datei.to")},
    {".hellshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hellshare.com")},
    {".hellshare.pl", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hellshare.pl")},
    {".hellshare.cz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hellshare.cz")},
    {".hellshare.sk", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hellshare.sk")},
    {".banashare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".banashare.com")},
    {".odsiebie.pl", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".odsiebie.pl")},
    {".sharebees.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".sharebees.com")},
    {".data.hu", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".data.hu")},
    {".yourfiles.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".yourfiles.to")},
    {".megarapid.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".megarapid.net")},
    {".fileshare.in.ua", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fileshare.in.ua")},
    {".share-rapid.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".share-rapid.com")},
    {".file-upload.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".file-upload.net")},
    {".load.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".load.to")},
    {".uploadingit.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploadingit.com")},
    {".najlepsze.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".najlepsze.net")},
    {".easy-share.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".easy-share.com")},
    {".sharebee.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".sharebee.com")},
    {".leteckaposta.cz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".leteckaposta.cz")},
    {".freespace.by", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".freespace.by")},
    {".filearning.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filearning.com")},
    {".megashare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".megashare.com")},
    {".megashare.info", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".megashare.info")},
    {".uploadking.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploadking.com")},
    {".uploadking.biz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploadking.biz")},
    {".asixfiles.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".asixfiles.com")},
    {".kewlshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".kewlshare.com")},
    {".edisk.cz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".edisk.cz")},
    {".up-file.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".up-file.com")},
    {".multishare.cz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".multishare.cz")},
    {".ifolder.ru", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".ifolder.ru")},
    {".uploader.cc", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploader.cc")},
    {".uploader.jp", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploader.jp")},
    {".uploader.pl", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".uploader.pl")},
    {".midupload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".midupload.com")},
    {".upnito.sk", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".upnito.sk")},
    {".fsx.hu", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fsx.hu")},
    {".euroshare.eu", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".euroshare.eu")},
    {".wrzuc.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".wrzuc.to")},
    {".dataport.cz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".dataport.cz")},
    {".terafiles.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".terafiles.net")},
    {".qshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".qshare.com")},
    {".netuploaded.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".netuploaded.com")},
    {".coolsharer.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".coolsharer.com")},
    {".fileupyours.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fileupyours.com")},
    {".massmirror.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".massmirror.com")},
    {".quickshare.cz", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".quickshare.cz")},
    {".i-filez.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".i-filez.com")},
    {".ftp2share.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".ftp2share.net")},
    {".filearn.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filearn.com")},
    {".filer.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filer.net")},
    {".speedshare.org", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".speedshare.org")},
    {".megasharez.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".megasharez.com")},
    {".fileover.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fileover.net")},
    {".files.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".files.to")},
    {".usershare.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".usershare.net")},
    {".hyperfileshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".hyperfileshare.com")},
    {".videobbs.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".videobbs.net")},
    {".multishared.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".multishared.com")},
    {".files-upload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".files-upload.com")},
    {".123upload.pl", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".123upload.pl")},
    {".1-clickshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".1-clickshare.com")},
    {".1-upload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".1-upload.com")},
    {".bestsharing.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".bestsharing.com")},
    {".bigfilez.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".bigfilez.com")},
    {".biggerupload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".biggerupload.com")},
    {".boosterking.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".boosterking.com")},
    {".cash-file.net", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".cash-file.net")},
    {".cobrashare.sk", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".cobrashare.sk")},
    {".data-loading.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".data-loading.com")},
    {".fastfileshare.com.ar", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".fastfileshare.com.ar")},
    {".filearchiv.ru", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filearchiv.ru")},
    {".filemaze.ws", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filemaze.ws")},
    {".files.mail.ru", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".files.mail.ru")},
    {".mytempdir.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".mytempdir.com")},
    {".putshare.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".putshare.com")},
    {".sanupload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".sanupload.com")},
    {".sharebase.to", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".sharebase.to")},
    {".upload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".upload.com")},
    {".thefile.me", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".thefile.me")},
    {".filenuke.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filenuke.com")},
    {".putme.org", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".putme.org")},
    {".filego.org", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".filego.org")},
    {".zooupload.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".zooupload.com")},
    {".wupfile.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".wupfile.com")},
    {".putlocker.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".putlocker.com")},
    {".sharerepo.com", PROTO_DIRECT_DOWNLOAD_LINK, MMT_STATICSTRING_LEN(".sharerepo.com")},

    // PROTO_BITTORRENT
    {".vuze.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".vuze.com")},
    {".firstclasstorrents.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".firstclasstorrents.com")},
    {".torrentprovider.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentprovider.com")},
    {".toorgle.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".toorgle.com")},
    {".extratorrent.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".extratorrent.com")},
    {".kat.ph", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".kat.ph")},
    {".kickasstorrents.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".kickasstorrents.com")},
    {".torrentz.eu", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentz.eu")},
    {".isohunt.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".isohunt.com")},
    {".nutorrent.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".nutorrent.com")},
    {".torrentdownloads.net", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentdownloads.net")},
    {".btdigg.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".btdigg.org")},
    {".eztv.it", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".eztv.it")},
    {".mininova.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".mininova.org")},
    {".torlock.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torlock.com")},
    {".seedpeer.me", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".seedpeer.me")},
    {".h33t.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".h33t.com")},
    {".bitsnoop.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bitsnoop.com")},
    {".torrenthound.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrenthound.com")},
    {".1337x.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".1337x.org")},
    {".vcdq.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".vcdq.com")},
    {".vertor.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".vertor.com")},
    {".seedpeer.me", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".seedpeer.me")},
    {".torrentfunk.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentfunk.com")},
    {".take.fm", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".take.fm")},
    {".monova.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".monova.org")},
    {".rarbg.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".rarbg.com")},
    {".limetorrents.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".limetorrents.com")},
    {".fulldls.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".fulldls.com")},
    {".torrentcrazy.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentcrazy.com")},
    {".torrents.to", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrents.to")},
    {".thunderbytes.net", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".thunderbytes.net")},
    {".fenopy.eu", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".fenopy.eu")},
    {".torrentzap.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentzap.com")},
    {".nowtorrents.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".nowtorrents.com")},
    {".torrentcafe.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torrentcafe.com")},
    {".qbittorrent.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".qbittorrent.org")},
    {".openbittorrent.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".openbittorrent.com")},
    {".bittorrental.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bittorrental.com")},
    {".bittorrent.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bittorrent.com")},
    {".bittorrentfiles.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bittorrentfiles.org")},
    {".bittorrent.am", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bittorrent.am")},
    {".bittorrent.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bittorrent.org")},
    {".yourbittorrent.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".yourbittorrent.com")},
    {".utorrent.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".utorrent.com")},
    {".btjunkie.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".btjunkie.org")},
    {".torcache.com", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".torcache.com")},
    {".bitlet.org", PROTO_BITTORRENT, MMT_STATICSTRING_LEN(".bitlet.org")},
	
    { NULL, 0, 0}
};

static protocol_match ak_cdn_url_start_with_names[] = {
    {"fbcdn-sphotos", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbcdn-sphotos"), MMT_CONTENT_CDN | MMT_CONTENT_IMAGE},
    {"fbstatic", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbstatic"), MMT_CONTENT_CDN},
    {"fbcdn-profile", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbcdn-profile"), MMT_CONTENT_CDN},
    {"fbcdn-video", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbcdn-video"), MMT_CONTENT_CDN | MMT_CONTENT_VIDEO},
    {"fbexternal", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbexternal"), MMT_CONTENT_CDN},
    {"fbcdn-photos", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbcdn-photos"), MMT_CONTENT_CDN | MMT_CONTENT_IMAGE},
    {"fbcdn", PROTO_FACEBOOK, MMT_STATICSTRING_LEN("fbcdn"), MMT_CONTENT_CDN},
    { NULL, 0, 0}
};

uint32_t get_proto_id_from_ak_cdn(ipacket_t * ipacket, char *hostname, u_int hostname_len) {
    int i = 0;
    while (ak_cdn_url_start_with_names[i].string_to_match != NULL) {
        if (hostname_len > ak_cdn_url_start_with_names[i].str_len && strncmp(hostname, ak_cdn_url_start_with_names[i].string_to_match, ak_cdn_url_start_with_names[i].str_len) == 0) {
            ipacket->session->content_flags = ipacket->session->content_flags | ak_cdn_url_start_with_names[i].content_flags;
            return ak_cdn_url_start_with_names[i].proto_id;
        }
        i++;
    }

    return PROTO_AKAMAI; //This is akamai anyway
}

uint32_t get_proto_id_from_address(ipacket_t * ipacket) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (packet->iph /* IPv4 only */) {

        /**
         * 
    Skype (Microsoft CDN)
    157.56.0.0/14, 157.60.0.0/16, 157.54.0.0/15
    111.221.64.0 - 111.221.127.255
    91.190.216.0/21 (AS198015 Skype Communications Sarl)
    40.126.129.109/32
    */

        if (    
                ((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x9D380000 /* 157.56.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x9D3C0000 /* 157.60.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFE0000 /* 255.254.0.0 */) == 0x9D360000 /* 157.54.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFC000 /* 255.255.192.0 */) == 0x6FDD4000 /* 111.221.64.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFF800 /* 255.255.248.0 */) == 0x5BBED800 /* 91.190.216.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFFFFF /* 0xFFFFFFFF */) == 0x287F816D /* 40.126.129.109 */)) {
            return PROTO_SKYPE;
        }

        /*
           Twitter 199.59.148.0/22
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC73B9400 /* 199.59.148.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC73B9400 /* 199.59.148.0 */)) {
            return PROTO_TWITTER;
        }

        /*
         * Facebook 69.171.224.0/19
         * 31.13.64.0 - 31.13.127.255/18 FB Ireland
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0x45ABE000 /* 69.171.224.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0x45ABE000 /* 69.171.224.0 */)
                || ((ntohl(packet->iph->saddr) & 0xFFFFC000 /* 255.255.292.0 */) == 0x1F0D4000 /* 31.13.64.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFC000 /* 255.255.292.0 */) == 0x1F0D4000 /* 31.13.64.0 */)) {
            if (packet->tcp != NULL && (packet->tcp->source == htons(8883) || packet->tcp->dest == htons(8883))) {
                return PROTO_FBMSG;
            }
            return PROTO_FACEBOOK;
        }


        /*
           NETFLIX-INC 69.53.224.0/19
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0x4535E000 /* 69.53.224.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0x4535E000 /* 69.53.224.0 */)) {
            return PROTO_NETFLIX;
        }

        /*
          Citrix GotoMeeting 216.115.208.0/20 AND 216.219.112.0/20
         */

        if (((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD873D000 /* 216.115.208.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD873D000 /* 216.115.208.0 */)
                || ((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD8DB7000 /* 216.219.112.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD8DB7000 /* 216.219.112.0 */)
                ) {
            return PROTO_CITRIXONLINE;
        }

        /*
           Apple 17.0.0.0/8
         */
        if (((ntohl(packet->iph->saddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)) {
            return PROTO_APPLE;
        }

        /*
          Webex 66.114.160.0/20
         */
        if (((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4272A000 /* 66.114.160.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4272A000 /* 66.114.160.0 */)) {
            return PROTO_WEBEX;
        }

        /*
          Google 173.194.0.0/16 AND 74.125.0.0/16
         */
        if ((((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xADC20000 /* 173.194.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xADC20000 /* 173.194.0.0 */)) ||
                (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x4A7D0000 /* 74.125.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x4A7D0000 /* 74.125.0.0 */))
                ) {
            if (packet->tcp != NULL && ((packet->tcp->source == htons(5228) || packet->tcp->dest == htons(5228)) ||
                    (packet->tcp->source == htons(5229) || packet->tcp->dest == htons(5229)) ||
                    (packet->tcp->source == htons(5230) || packet->tcp->dest == htons(5230)))) {
                return PROTO_GCM;
            }
            return PROTO_GOOGLE;
        }

        /*
          Yahoo 98.136.0.0/14
         */
        if ((((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x62880000 /* 98.136.0.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.252.0.0 */) == 0x62880000 /* 98.136.0.0 */))
                ) {
            return PROTO_YAHOO;
        }
        /*
          AmazonAWS 207.171.160.0/19
         */
        if ((((ntohl(packet->iph->saddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0xCFABA000 /* 207.171.160.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFE000 /* 255.255.224.0 */) == 0xCFABA000 /* 207.171.160.0 */))
                ) {
            return PROTO_AMAZON;
        }

        /*
          Kakao 110.76.140.0 - 110.76.143.255/22
         */
        if ((((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x6E4C8C00 /* 110.76.140.0 */)
                || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x6E4C8C00 /* 110.76.140.0 */))
                ) {
            return PROTO_KAKAO;
        }
    }
    return PROTO_UNKNOWN;
}

uint32_t get_proto_id_by_hostname(ipacket_t * ipacket, char *hostname, u_int hostname_len) {
    int i = 0;
    //struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    while ( __builtin_expect( doted_host_names[i].string_to_match != NULL, 1 )) {
        if (_mmt_case_sensitive_reverse_hostname_matching(hostname, doted_host_names[i].string_to_match, hostname_len, doted_host_names[i].str_len)) {
            ipacket->session->content_flags = ipacket->session->content_flags | doted_host_names[i].content_flags;
            if (doted_host_names[i].proto_id == PROTO_AKAMAI) {
                return get_proto_id_from_ak_cdn(ipacket, hostname, hostname_len);
            }
            return doted_host_names[i].proto_id;
        }
        i++;
    }

    return PROTO_UNKNOWN;
}
