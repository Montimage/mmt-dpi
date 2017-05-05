#include <stdio.h>
#include <stdlib.h>
#include "mmt_common_internal_include.h"
#include "../include/mmt_tcpip_plugin.h"
#include "../include/mmt_tcpip_protocols.h"

int init_proto() {
    return init_tcpip_plugin();
}

int cleanup_proto(){
    return cleanup_tcpip_plugin();
}

int cleanup_tcpip_plugin(){
    // if(!cleanup_proto_tcp_struct()){
    //     fprintf(stderr, "No cleanup function for protocol proto_tcp\n");
    // }
    return 1;
}

int init_tcpip_plugin() {
    int retval = 1;

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////START OF GENERATED CODE --- DO NOT MODIFY ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    /////////// INITILIZING PROTO_163 //////////////////
    if (!init_proto_163_struct()) {
        fprintf(stderr, "Error initializing protocol proto_163\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_360 //////////////////
    if (!init_proto_360_struct()) {
        fprintf(stderr, "Error initializing protocol proto_360\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_302_FOUND //////////////////
    if (!init_proto_302_found_struct()) {
        fprintf(stderr, "Error initializing protocol proto_302_found\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_jd //////////////////
    if (!init_proto_jd_struct()) {
        fprintf(stderr, "Error initializing protocol proto_jd\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_56 //////////////////
    if (!init_proto_56_struct()) {
        fprintf(stderr, "Error initializing protocol proto_56\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_8021Q //////////////////
    if (!init_proto_8021q_struct()) {
        fprintf(stderr, "Error initializing protocol proto_8021q\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_888 //////////////////
    if (!init_proto_888_struct()) {
        fprintf(stderr, "Error initializing protocol proto_888\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ABOUT //////////////////
    if (!init_proto_about_struct()) {
        fprintf(stderr, "Error initializing protocol proto_about\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ADCASH //////////////////
    if (!init_proto_adcash_struct()) {
        fprintf(stderr, "Error initializing protocol proto_adcash\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ADDTHIS //////////////////
    if (!init_proto_addthis_struct()) {
        fprintf(stderr, "Error initializing protocol proto_addthis\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ADF //////////////////
    if (!init_proto_adf_struct()) {
        fprintf(stderr, "Error initializing protocol proto_adf\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ADOBE //////////////////
    if (!init_proto_adobe_struct()) {
        fprintf(stderr, "Error initializing protocol proto_adobe\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AFP //////////////////
    if (!init_proto_afp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_afp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AH //////////////////
    if (!init_proto_ah_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ah\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AIM //////////////////
    if (!init_proto_aim_struct()) {
        fprintf(stderr, "Error initializing protocol proto_aim\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AIMINI //////////////////
    if (!init_proto_aimini_struct()) {
        fprintf(stderr, "Error initializing protocol proto_aimini\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ALIBABA //////////////////
    if (!init_proto_alibaba_struct()) {
        fprintf(stderr, "Error initializing protocol proto_alibaba\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ALIPAY //////////////////
    if (!init_proto_alipay_struct()) {
        fprintf(stderr, "Error initializing protocol proto_alipay\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ALLEGRO //////////////////
    if (!init_proto_allegro_struct()) {
        fprintf(stderr, "Error initializing protocol proto_allegro\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AMAZON //////////////////
    if (!init_proto_amazon_struct()) {
        fprintf(stderr, "Error initializing protocol proto_amazon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AMEBLO //////////////////
    if (!init_proto_ameblo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ameblo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ANCESTRY //////////////////
    if (!init_proto_ancestry_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ancestry\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ANGRYBIRDS //////////////////
    if (!init_proto_angrybirds_struct()) {
        fprintf(stderr, "Error initializing protocol proto_angrybirds\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ANSWERS //////////////////
    if (!init_proto_answers_struct()) {
        fprintf(stderr, "Error initializing protocol proto_answers\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AOL //////////////////
    if (!init_proto_aol_struct()) {
        fprintf(stderr, "Error initializing protocol proto_aol\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLE //////////////////
    if (!init_proto_apple_struct()) {
        fprintf(stderr, "Error initializing protocol proto_apple\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLEJUICE //////////////////
    if (!init_proto_applejuice_struct()) {
        fprintf(stderr, "Error initializing protocol proto_applejuice\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARMAGETRON //////////////////
    if (!init_proto_armagetron_struct()) {
        fprintf(stderr, "Error initializing protocol proto_armagetron\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARP //////////////////
    if (!init_proto_arp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_arp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASK //////////////////
    if (!init_proto_ask_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ask\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AVG //////////////////
    if (!init_proto_avg_struct()) {
        fprintf(stderr, "Error initializing protocol proto_avg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AVI //////////////////
    if (!init_proto_avi_struct()) {
        fprintf(stderr, "Error initializing protocol proto_avi\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AWEBER //////////////////
    if (!init_proto_aweber_struct()) {
        fprintf(stderr, "Error initializing protocol proto_aweber\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AWS //////////////////
    if (!init_proto_aws_struct()) {
        fprintf(stderr, "Error initializing protocol proto_aws\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BABYLON //////////////////
    if (!init_proto_babylon_struct()) {
        fprintf(stderr, "Error initializing protocol proto_babylon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BADOO //////////////////
    if (!init_proto_badoo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_badoo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BAIDU //////////////////
    if (!init_proto_baidu_struct()) {
        fprintf(stderr, "Error initializing protocol proto_baidu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BANKOFAMERICA //////////////////
    if (!init_proto_bankofamerica_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bankofamerica\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BARNESANDNOBLE //////////////////
    if (!init_proto_barnesandnoble_struct()) {
        fprintf(stderr, "Error initializing protocol proto_barnesandnoble\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BATMAN //////////////////
    if (!init_proto_batman_struct()) {
        fprintf(stderr, "Error initializing protocol proto_batman\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BATTLEFIELD //////////////////
    if (!init_proto_battlefield_struct()) {
        fprintf(stderr, "Error initializing protocol proto_battlefield\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BATTLENET //////////////////
    if (!init_proto_battlenet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_battlenet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BBB //////////////////
    if (!init_proto_bbb_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bbb\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BBC_ONLINE //////////////////
    if (!init_proto_bbc_online_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bbc_online\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BESTBUY //////////////////
    if (!init_proto_bestbuy_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bestbuy\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BETFAIR //////////////////
    if (!init_proto_betfair_struct()) {
        fprintf(stderr, "Error initializing protocol proto_betfair\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BGP //////////////////
    if (!init_proto_bgp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bgp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BIBLEGATEWAY //////////////////
    if (!init_proto_biblegateway_struct()) {
        fprintf(stderr, "Error initializing protocol proto_biblegateway\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BILD //////////////////
    if (!init_proto_bild_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bild\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BING //////////////////
    if (!init_proto_bing_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bing\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BITTORRENT //////////////////
    if (!init_proto_bittorrent_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bittorrent\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLEACHERREPORT //////////////////
    if (!init_proto_bleacherreport_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bleacherreport\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLOGFA //////////////////
    if (!init_proto_blogfa_struct()) {
        fprintf(stderr, "Error initializing protocol proto_blogfa\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLOGGER //////////////////
    if (!init_proto_blogger_struct()) {
        fprintf(stderr, "Error initializing protocol proto_blogger\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLOGSPOT //////////////////
    if (!init_proto_blogspot_struct()) {
        fprintf(stderr, "Error initializing protocol proto_blogspot\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BODYBUILDING //////////////////
    if (!init_proto_bodybuilding_struct()) {
        fprintf(stderr, "Error initializing protocol proto_bodybuilding\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BOOKING //////////////////
    if (!init_proto_booking_struct()) {
        fprintf(stderr, "Error initializing protocol proto_booking\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CBSSPORTS //////////////////
    if (!init_proto_cbssports_struct()) {
        fprintf(stderr, "Error initializing protocol proto_cbssports\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CENT //////////////////
    if (!init_proto_cent_struct()) {
        fprintf(stderr, "Error initializing protocol proto_cent\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHANGE //////////////////
    if (!init_proto_change_struct()) {
        fprintf(stderr, "Error initializing protocol proto_change\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHASE //////////////////
    if (!init_proto_chase_struct()) {
        fprintf(stderr, "Error initializing protocol proto_chase\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHESS //////////////////
    if (!init_proto_chess_struct()) {
        fprintf(stderr, "Error initializing protocol proto_chess\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHINAZ //////////////////
    if (!init_proto_chinaz_struct()) {
        fprintf(stderr, "Error initializing protocol proto_chinaz\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CITRIX //////////////////
    if (!init_proto_citrix_struct()) {
        fprintf(stderr, "Error initializing protocol proto_citrix\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CITRIXONLINE //////////////////
    if (!init_proto_citrixonline_struct()) {
        fprintf(stderr, "Error initializing protocol proto_citrixonline\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CLICKSOR //////////////////
    if (!init_proto_clicksor_struct()) {
        fprintf(stderr, "Error initializing protocol proto_clicksor\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CNN //////////////////
    if (!init_proto_cnn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_cnn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CNZZ //////////////////
    if (!init_proto_cnzz_struct()) {
        fprintf(stderr, "Error initializing protocol proto_cnzz\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMCAST //////////////////
    if (!init_proto_comcast_struct()) {
        fprintf(stderr, "Error initializing protocol proto_comcast\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CONDUIT //////////////////
    if (!init_proto_conduit_struct()) {
        fprintf(stderr, "Error initializing protocol proto_conduit\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_COPYSCAPE //////////////////
    if (!init_proto_copyscape_struct()) {
        fprintf(stderr, "Error initializing protocol proto_copyscape\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CORREIOS //////////////////
    if (!init_proto_correios_struct()) {
        fprintf(stderr, "Error initializing protocol proto_correios\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CRAIGSLIST //////////////////
    if (!init_proto_craigslist_struct()) {
        fprintf(stderr, "Error initializing protocol proto_craigslist\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CROSSFIRE //////////////////
    if (!init_proto_crossfire_struct()) {
        fprintf(stderr, "Error initializing protocol proto_crossfire\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DAILYMAIL //////////////////
    if (!init_proto_dailymail_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dailymail\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DAILYMOTION //////////////////
    if (!init_proto_dailymotion_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dailymotion\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DCERPC //////////////////
    if (!init_proto_dcerpc_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dcerpc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DIRECT_DOWNLOAD_LINK //////////////////
    if (!init_proto_direct_download_link_struct()) {
        fprintf(stderr, "Error initializing protocol proto_direct_download_link\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEVIANTART //////////////////
    if (!init_proto_deviantart_struct()) {
        fprintf(stderr, "Error initializing protocol proto_deviantart\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DHCP //////////////////
    if (!init_proto_dhcp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dhcp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DHCPV6 //////////////////
    if (!init_proto_dhcpv6_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dhcpv6\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DIGG //////////////////
    if (!init_proto_digg_struct()) {
        fprintf(stderr, "Error initializing protocol proto_digg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DIRECTCONNECT //////////////////
    if (!init_proto_directconnect_struct()) {
        fprintf(stderr, "Error initializing protocol proto_directconnect\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DNS //////////////////
    if (!init_proto_dns_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dns\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DOFUS //////////////////
    if (!init_proto_dofus_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dofus\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DONANIMHABER //////////////////
    if (!init_proto_donanimhaber_struct()) {
        fprintf(stderr, "Error initializing protocol proto_donanimhaber\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DOUBAN //////////////////
    if (!init_proto_douban_struct()) {
        fprintf(stderr, "Error initializing protocol proto_douban\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DOUBLECLICK //////////////////
    if (!init_proto_doubleclick_struct()) {
        fprintf(stderr, "Error initializing protocol proto_doubleclick\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DROPBOX //////////////////
    if (!init_proto_dropbox_struct()) {
        fprintf(stderr, "Error initializing protocol proto_dropbox\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EBAY //////////////////
    if (!init_proto_ebay_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ebay\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EDONKEY //////////////////
    if (!init_proto_edonkey_struct()) {
        fprintf(stderr, "Error initializing protocol proto_edonkey\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EGP //////////////////
    if (!init_proto_egp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_egp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EHOW //////////////////
    if (!init_proto_ehow_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ehow\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EKSISOZLUK //////////////////
    if (!init_proto_eksisozluk_struct()) {
        fprintf(stderr, "Error initializing protocol proto_eksisozluk\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ELECTRONICSARTS //////////////////
    if (!init_proto_electronicsarts_struct()) {
        fprintf(stderr, "Error initializing protocol proto_electronicsarts\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ESP //////////////////
    if (!init_proto_esp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_esp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ESPN //////////////////
    if (!init_proto_espn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_espn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ETHERNET //////////////////
    if (!init_proto_ethernet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ethernet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ETSY //////////////////
    if (!init_proto_etsy_struct()) {
        fprintf(stderr, "Error initializing protocol proto_etsy\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EUROPA //////////////////
    if (!init_proto_europa_struct()) {
        fprintf(stderr, "Error initializing protocol proto_europa\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EUROSPORT //////////////////
    if (!init_proto_eurosport_struct()) {
        fprintf(stderr, "Error initializing protocol proto_eurosport\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FACEBOOK //////////////////
    if (!init_proto_facebook_struct()) {
        fprintf(stderr, "Error initializing protocol proto_facebook\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FACETIME //////////////////
    if (!init_proto_facetime_struct()) {
        fprintf(stderr, "Error initializing protocol proto_facetime\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FASTTRACK //////////////////
    if (!init_proto_fasttrack_struct()) {
        fprintf(stderr, "Error initializing protocol proto_fasttrack\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FC2 //////////////////
    if (!init_proto_fc2_struct()) {
        fprintf(stderr, "Error initializing protocol proto_fc2\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FEIDIAN //////////////////
    if (!init_proto_feidian_struct()) {
        fprintf(stderr, "Error initializing protocol proto_feidian\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FIESTA //////////////////
    if (!init_proto_fiesta_struct()) {
        fprintf(stderr, "Error initializing protocol proto_fiesta\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FILETOPIA //////////////////
    if (!init_proto_filetopia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_filetopia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FIVERR //////////////////
    if (!init_proto_fiverr_struct()) {
        fprintf(stderr, "Error initializing protocol proto_fiverr\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FLASH //////////////////
    if (!init_proto_flash_struct()) {
        fprintf(stderr, "Error initializing protocol proto_flash\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FLICKR //////////////////
    if (!init_proto_flickr_struct()) {
        fprintf(stderr, "Error initializing protocol proto_flickr\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FLORENSIA //////////////////
    if (!init_proto_florensia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_florensia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FOURSQUARE //////////////////
    if (!init_proto_foursquare_struct()) {
        fprintf(stderr, "Error initializing protocol proto_foursquare\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FOX //////////////////
    if (!init_proto_fox_struct()) {
        fprintf(stderr, "Error initializing protocol proto_fox\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FREE //////////////////
    if (!init_proto_free_struct()) {
        fprintf(stderr, "Error initializing protocol proto_free\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FTP //////////////////
    if (!init_proto_ftp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ftp\n Exiting\n");
        exit(0);
    }

    // if (!init_proto_ftp_control_struct()) {
    //     fprintf(stderr, "Error initializing protocol proto_ftp_control\n Exiting\n");
    //     exit(0);
    // }

    // if (!init_proto_ftp_data_struct()) {
    //     fprintf(stderr, "Error initializing protocol proto_ftp_data\n Exiting\n");
    //     exit(0);
    // }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NDN //////////////////
    if (!init_proto_ndn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ndn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NDN_HTTP //////////////////
    if (!init_proto_ndn_http_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ndn_http\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GADUGADU //////////////////
    if (!init_proto_gadugadu_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gadugadu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GAMEFAQS //////////////////
    if (!init_proto_gamefaqs_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gamefaqs\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GAMESPOT //////////////////
    if (!init_proto_gamespot_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gamespot\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GAP //////////////////
    if (!init_proto_gap_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gap\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GARANTI //////////////////
    if (!init_proto_garanti_struct()) {
        fprintf(stderr, "Error initializing protocol proto_garanti\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GAZETEVATAN //////////////////
    if (!init_proto_gazetevatan_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gazetevatan\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GIGAPETA //////////////////
    if (!init_proto_gigapeta_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gigapeta\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GITHUB //////////////////
    if (!init_proto_github_struct()) {
        fprintf(stderr, "Error initializing protocol proto_github\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GITTIGIDIYOR //////////////////
    if (!init_proto_gittigidiyor_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gittigidiyor\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GLOBO //////////////////
    if (!init_proto_globo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_globo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GMAIL //////////////////
    if (!init_proto_gmail_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gmail\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GNUTELLA //////////////////
    if (!init_proto_gnutella_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gnutella\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GOOGLE_MAPS //////////////////
    if (!init_proto_google_maps_struct()) {
        fprintf(stderr, "Error initializing protocol proto_google_maps\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GO //////////////////
    if (!init_proto_go_struct()) {
        fprintf(stderr, "Error initializing protocol proto_go\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GODADDY //////////////////
    if (!init_proto_godaddy_struct()) {
        fprintf(stderr, "Error initializing protocol proto_godaddy\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GOO //////////////////
    if (!init_proto_goo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_goo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GOOGLE //////////////////
    if (!init_proto_google_struct()) {
        fprintf(stderr, "Error initializing protocol proto_google\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GOOGLE_USER_CONTENT //////////////////
    if (!init_proto_google_user_content_struct()) {
        fprintf(stderr, "Error initializing protocol proto_google_user_content\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GOSMS //////////////////
    if (!init_proto_gosms_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gosms\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GRE //////////////////
    if (!init_proto_gre_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gre\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GROOVESHARK //////////////////
    if (!init_proto_grooveshark_struct()) {
        fprintf(stderr, "Error initializing protocol proto_grooveshark\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GROUPON //////////////////
    if (!init_proto_groupon_struct()) {
        fprintf(stderr, "Error initializing protocol proto_groupon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GTALK //////////////////
    if (!init_proto_gtalk_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gtalk\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GTP //////////////////
    if (!init_proto_gtp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GTP2 //////////////////
    if (!init_proto_gtp2_struct()) {
        fprintf(stderr, "Error initializing protocol proto_gtp2\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GUARDIAN //////////////////
    if (!init_proto_guardian_struct()) {
        fprintf(stderr, "Error initializing protocol proto_guardian\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GUILDWARS //////////////////
    if (!init_proto_guildwars_struct()) {
        fprintf(stderr, "Error initializing protocol proto_guildwars\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HABERTURK //////////////////
    if (!init_proto_haberturk_struct()) {
        fprintf(stderr, "Error initializing protocol proto_haberturk\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HAO123 //////////////////
    if (!init_proto_hao123_struct()) {
        fprintf(stderr, "Error initializing protocol proto_hao123\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HEPSIBURADA //////////////////
    if (!init_proto_hepsiburada_struct()) {
        fprintf(stderr, "Error initializing protocol proto_hepsiburada\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HI5 //////////////////
    if (!init_proto_hi5_struct()) {
        fprintf(stderr, "Error initializing protocol proto_hi5\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HALFLIFE2 //////////////////
    if (!init_proto_halflife2_struct()) {
        fprintf(stderr, "Error initializing protocol proto_halflife2\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HOMEDEPOT //////////////////
    if (!init_proto_homedepot_struct()) {
        fprintf(stderr, "Error initializing protocol proto_homedepot\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HOOTSUITE //////////////////
    if (!init_proto_hootsuite_struct()) {
        fprintf(stderr, "Error initializing protocol proto_hootsuite\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HOTMAIL //////////////////
    if (!init_proto_hotmail_struct()) {
        fprintf(stderr, "Error initializing protocol proto_hotmail\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP //////////////////
    if (!init_proto_http_struct()) {
        fprintf(stderr, "Error initializing protocol proto_http\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_CONNECT //////////////////
    if (!init_proto_http_connect_struct()) {
        fprintf(stderr, "Error initializing protocol proto_http_connect\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_PROXY //////////////////
    if (!init_proto_http_proxy_struct()) {
        fprintf(stderr, "Error initializing protocol proto_http_proxy\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_APPLICATION_ACTIVESYNC //////////////////
    if (!init_proto_http_application_activesync_struct()) {
        fprintf(stderr, "Error initializing protocol proto_http_application_activesync\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HUFFINGTONPOST //////////////////
    if (!init_proto_huffingtonpost_struct()) {
        fprintf(stderr, "Error initializing protocol proto_huffingtonpost\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HURRIYET //////////////////
    if (!init_proto_hurriyet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_hurriyet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_I23V5 //////////////////
    if (!init_proto_i23v5_struct()) {
        fprintf(stderr, "Error initializing protocol proto_i23v5\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IAX //////////////////
    if (!init_proto_iax_struct()) {
        fprintf(stderr, "Error initializing protocol proto_iax\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ICECAST //////////////////
    if (!init_proto_icecast_struct()) {
        fprintf(stderr, "Error initializing protocol proto_icecast\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLE_ICLOUD //////////////////
    if (!init_proto_apple_icloud_struct()) {
        fprintf(stderr, "Error initializing protocol proto_apple_icloud\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ICMP //////////////////
    if (!init_proto_icmp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_icmp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ICMPV6 //////////////////
    if (!init_proto_icmpv6_struct()) {
        fprintf(stderr, "Error initializing protocol proto_icmpv6\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IFENG //////////////////
    if (!init_proto_ifeng_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ifeng\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IGMP //////////////////
    if (!init_proto_igmp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_igmp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IGN //////////////////
    if (!init_proto_ign_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ign\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IKEA //////////////////
    if (!init_proto_ikea_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ikea\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMAP //////////////////
    if (!init_proto_imap_struct()) {
        fprintf(stderr, "Error initializing protocol proto_imap\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMAPS //////////////////
    if (!init_proto_imaps_struct()) {
        fprintf(stderr, "Error initializing protocol proto_imaps\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMDB //////////////////
    if (!init_proto_imdb_struct()) {
        fprintf(stderr, "Error initializing protocol proto_imdb\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMESH //////////////////
    if (!init_proto_imesh_struct()) {
        fprintf(stderr, "Error initializing protocol proto_imesh\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMESSAGE //////////////////
    if (!init_proto_imessage_struct()) {
        fprintf(stderr, "Error initializing protocol proto_imessage\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMGUR //////////////////
    if (!init_proto_imgur_struct()) {
        fprintf(stderr, "Error initializing protocol proto_imgur\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_INCREDIBAR //////////////////
    if (!init_proto_incredibar_struct()) {
        fprintf(stderr, "Error initializing protocol proto_incredibar\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_INDIATIMES //////////////////
    if (!init_proto_indiatimes_struct()) {
        fprintf(stderr, "Error initializing protocol proto_indiatimes\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_INSTAGRAM //////////////////
    if (!init_proto_instagram_struct()) {
        fprintf(stderr, "Error initializing protocol proto_instagram\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IP //////////////////
    if (!init_proto_ip_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IP_IN_IP //////////////////
    if (!init_proto_ip_in_ip_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ip_in_ip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPP //////////////////
    if (!init_proto_ipp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ipp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPSEC //////////////////
    if (!init_proto_ipsec_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ipsec\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPV6 //////////////////
    if (!init_proto_ipv6_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ipv6\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRC //////////////////
    if (!init_proto_irc_struct()) {
        fprintf(stderr, "Error initializing protocol proto_irc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRS //////////////////
    if (!init_proto_irs_struct()) {
        fprintf(stderr, "Error initializing protocol proto_irs\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLE_ITUNES //////////////////
    if (!init_proto_apple_itunes_struct()) {
        fprintf(stderr, "Error initializing protocol proto_apple_itunes\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UNENCRYPED_JABBER //////////////////
    if (!init_proto_unencryped_jabber_struct()) {
        fprintf(stderr, "Error initializing protocol proto_unencryped_jabber\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_JAPANPOST //////////////////
    if (!init_proto_japanpost_struct()) {
        fprintf(stderr, "Error initializing protocol proto_japanpost\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KAKAO //////////////////
    if (!init_proto_kakao_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kakao\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KAT //////////////////
    if (!init_proto_kat_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kat\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KAZAA //////////////////
    if (!init_proto_kazaa_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kazaa\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KERBEROS //////////////////
    if (!init_proto_kerberos_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kerberos\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KING //////////////////
    if (!init_proto_king_struct()) {
        fprintf(stderr, "Error initializing protocol proto_king\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KOHLS //////////////////
    if (!init_proto_kohls_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kohls\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KONGREGATE //////////////////
    if (!init_proto_kongregate_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kongregate\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KONTIKI //////////////////
    if (!init_proto_kontiki_struct()) {
        fprintf(stderr, "Error initializing protocol proto_kontiki\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_L2TP //////////////////
    if (!init_proto_l2tp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_l2tp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LASTFM //////////////////
    if (!init_proto_lastfm_struct()) {
        fprintf(stderr, "Error initializing protocol proto_lastfm\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LDAP //////////////////
    if (!init_proto_ldap_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ldap\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEAGUEOFLEGENDS //////////////////
    if (!init_proto_leagueoflegends_struct()) {
        fprintf(stderr, "Error initializing protocol proto_leagueoflegends\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEGACY //////////////////
    if (!init_proto_legacy_struct()) {
        fprintf(stderr, "Error initializing protocol proto_legacy\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LETV //////////////////
    if (!init_proto_letv_struct()) {
        fprintf(stderr, "Error initializing protocol proto_letv\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LINKEDIN //////////////////
    if (!init_proto_linkedin_struct()) {
        fprintf(stderr, "Error initializing protocol proto_linkedin\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVE //////////////////
    if (!init_proto_live_struct()) {
        fprintf(stderr, "Error initializing protocol proto_live\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVEDOOR //////////////////
    if (!init_proto_livedoor_struct()) {
        fprintf(stderr, "Error initializing protocol proto_livedoor\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVEHOTMAIL //////////////////
    if (!init_proto_livehotmail_struct()) {
        fprintf(stderr, "Error initializing protocol proto_livehotmail\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVEINTERNET //////////////////
    if (!init_proto_liveinternet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_liveinternet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVEJASMIN //////////////////
    if (!init_proto_livejasmin_struct()) {
        fprintf(stderr, "Error initializing protocol proto_livejasmin\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVEJOURNAL //////////////////
    if (!init_proto_livejournal_struct()) {
        fprintf(stderr, "Error initializing protocol proto_livejournal\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVESCORE //////////////////
    if (!init_proto_livescore_struct()) {
        fprintf(stderr, "Error initializing protocol proto_livescore\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVINGSOCIAL //////////////////
    if (!init_proto_livingsocial_struct()) {
        fprintf(stderr, "Error initializing protocol proto_livingsocial\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LOWES //////////////////
    if (!init_proto_lowes_struct()) {
        fprintf(stderr, "Error initializing protocol proto_lowes\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MACYS //////////////////
    if (!init_proto_macys_struct()) {
        fprintf(stderr, "Error initializing protocol proto_macys\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAIL_RU //////////////////
    if (!init_proto_mail_ru_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mail_ru\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MANET //////////////////
    if (!init_proto_manet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_manet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MANOLITO //////////////////
    if (!init_proto_manolito_struct()) {
        fprintf(stderr, "Error initializing protocol proto_manolito\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAPLESTORY //////////////////
    if (!init_proto_maplestory_struct()) {
        fprintf(stderr, "Error initializing protocol proto_maplestory\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MATCH //////////////////
    if (!init_proto_match_struct()) {
        fprintf(stderr, "Error initializing protocol proto_match\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MDNS //////////////////
    if (!init_proto_mdns_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mdns\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MEDIAFIRE //////////////////
    if (!init_proto_mediafire_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mediafire\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MEEBO //////////////////
    if (!init_proto_meebo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_meebo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MGCP //////////////////
    if (!init_proto_mgcp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mgcp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MICROSOFT //////////////////
    if (!init_proto_microsoft_struct()) {
        fprintf(stderr, "Error initializing protocol proto_microsoft\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MILLIYET //////////////////
    if (!init_proto_milliyet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_milliyet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MINECRAFT //////////////////
    if (!init_proto_minecraft_struct()) {
        fprintf(stderr, "Error initializing protocol proto_minecraft\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MINICLIP //////////////////
    if (!init_proto_miniclip_struct()) {
        fprintf(stderr, "Error initializing protocol proto_miniclip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MLBASEBALL //////////////////
    if (!init_proto_mlbaseball_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mlbaseball\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MMO-CHAMPION //////////////////
    if (!init_proto_mmo_champion_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mmo-champion\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MMS //////////////////
    if (!init_proto_mms_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mms\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MOVE //////////////////
    if (!init_proto_move_struct()) {
        fprintf(stderr, "Error initializing protocol proto_move\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MOZILLA //////////////////
    if (!init_proto_mozilla_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mozilla\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPEG //////////////////
    if (!init_proto_mpeg_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mpeg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSN //////////////////
    if (!init_proto_msn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_msn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSSQL //////////////////
    if (!init_proto_mssql_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mssql\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MULTIPLY //////////////////
    if (!init_proto_multiply_struct()) {
        fprintf(stderr, "Error initializing protocol proto_multiply\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MYNET //////////////////
    if (!init_proto_mynet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mynet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MYSPACE //////////////////
    if (!init_proto_myspace_struct()) {
        fprintf(stderr, "Error initializing protocol proto_myspace\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MYSQL //////////////////
    if (!init_proto_mysql_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mysql\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MYWEBSEARCH //////////////////
    if (!init_proto_mywebsearch_struct()) {
        fprintf(stderr, "Error initializing protocol proto_mywebsearch\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NBA //////////////////
    if (!init_proto_nba_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nba\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NEOBUX //////////////////
    if (!init_proto_neobux_struct()) {
        fprintf(stderr, "Error initializing protocol proto_neobux\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETBIOS //////////////////
    if (!init_proto_netbios_struct()) {
        fprintf(stderr, "Error initializing protocol proto_netbios\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETFLIX //////////////////
    if (!init_proto_netflix_struct()) {
        fprintf(stderr, "Error initializing protocol proto_netflix\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETFLOW //////////////////
    if (!init_proto_netflow_struct()) {
        fprintf(stderr, "Error initializing protocol proto_netflow\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NEWEGG //////////////////
    if (!init_proto_newegg_struct()) {
        fprintf(stderr, "Error initializing protocol proto_newegg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NEWSMAX //////////////////
    if (!init_proto_newsmax_struct()) {
        fprintf(stderr, "Error initializing protocol proto_newsmax\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NFL //////////////////
    if (!init_proto_nfl_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nfl\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NFS //////////////////
    if (!init_proto_nfs_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nfs\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NICOVIDEO //////////////////
    if (!init_proto_nicovideo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nicovideo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NIH //////////////////
    if (!init_proto_nih_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nih\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NORDSTROM //////////////////
    if (!init_proto_nordstrom_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nordstrom\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NTP //////////////////
    if (!init_proto_ntp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ntp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NYTIMES //////////////////
    if (!init_proto_nytimes_struct()) {
        fprintf(stderr, "Error initializing protocol proto_nytimes\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ODNOKLASSNIKI //////////////////
    if (!init_proto_odnoklassniki_struct()) {
        fprintf(stderr, "Error initializing protocol proto_odnoklassniki\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OFF //////////////////
    if (!init_proto_off_struct()) {
        fprintf(stderr, "Error initializing protocol proto_off\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OGG //////////////////
    if (!init_proto_ogg_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ogg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ONET //////////////////
    if (!init_proto_onet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_onet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPENFT //////////////////
    if (!init_proto_openft_struct()) {
        fprintf(stderr, "Error initializing protocol proto_openft\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ORANGEDONKEY //////////////////
    if (!init_proto_orangedonkey_struct()) {
        fprintf(stderr, "Error initializing protocol proto_orangedonkey\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OSCAR //////////////////
    if (!init_proto_oscar_struct()) {
        fprintf(stderr, "Error initializing protocol proto_oscar\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OSPF //////////////////
    if (!init_proto_ospf_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ospf\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OUTBRAIN //////////////////
    if (!init_proto_outbrain_struct()) {
        fprintf(stderr, "Error initializing protocol proto_outbrain\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OVERSTOCK //////////////////
    if (!init_proto_overstock_struct()) {
        fprintf(stderr, "Error initializing protocol proto_overstock\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PANDO //////////////////
    if (!init_proto_pando_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pando\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PAYPAL //////////////////
    if (!init_proto_paypal_struct()) {
        fprintf(stderr, "Error initializing protocol proto_paypal\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PCANYWHERE //////////////////
    if (!init_proto_pcanywhere_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pcanywhere\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PCH //////////////////
    if (!init_proto_pch_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pch\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PCONLINE //////////////////
    if (!init_proto_pconline_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pconline\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PHOTOBUCKET //////////////////
    if (!init_proto_photobucket_struct()) {
        fprintf(stderr, "Error initializing protocol proto_photobucket\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PINTEREST //////////////////
    if (!init_proto_pinterest_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pinterest\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PLAYSTATION //////////////////
    if (!init_proto_playstation_struct()) {
        fprintf(stderr, "Error initializing protocol proto_playstation\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_POGO //////////////////
    if (!init_proto_pogo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pogo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_POP //////////////////
    if (!init_proto_pop_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pop\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_POPS //////////////////
    if (!init_proto_pops_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pops\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_POPO //////////////////
    if (!init_proto_popo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_popo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PORNHUB //////////////////
    if (!init_proto_pornhub_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pornhub\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_POSTGRES //////////////////
    if (!init_proto_postgres_struct()) {
        fprintf(stderr, "Error initializing protocol proto_postgres\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PPLIVE //////////////////
    if (!init_proto_pplive_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pplive\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PPP //////////////////
    if (!init_proto_ppp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ppp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PPPoE //////////////////
    if (!init_proto_pppoe_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pppoe\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PPSTREAM //////////////////
    if (!init_proto_ppstream_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ppstream\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PPTP //////////////////
    if (!init_proto_pptp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_pptp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PREMIERLEAGUE //////////////////
    if (!init_proto_premierleague_struct()) {
        fprintf(stderr, "Error initializing protocol proto_premierleague\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_QQ //////////////////
    if (!init_proto_qq_struct()) {
        fprintf(stderr, "Error initializing protocol proto_qq\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_QQLIVE //////////////////
    if (!init_proto_qqlive_struct()) {
        fprintf(stderr, "Error initializing protocol proto_qqlive\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_QUAKE //////////////////
    if (!init_proto_quake_struct()) {
        fprintf(stderr, "Error initializing protocol proto_quake\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_QUICKTIME //////////////////
    if (!init_proto_quicktime_struct()) {
        fprintf(stderr, "Error initializing protocol proto_quicktime\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_R10 //////////////////
    if (!init_proto_r10_struct()) {
        fprintf(stderr, "Error initializing protocol proto_r10\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RADIUS //////////////////
    if (!init_proto_radius_struct()) {
        fprintf(stderr, "Error initializing protocol proto_radius\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RAKUTEN //////////////////
    if (!init_proto_rakuten_struct()) {
        fprintf(stderr, "Error initializing protocol proto_rakuten\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RDP //////////////////
    if (!init_proto_rdp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_rdp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_REALMEDIA //////////////////
    if (!init_proto_realmedia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_realmedia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_REDDIT //////////////////
    if (!init_proto_reddit_struct()) {
        fprintf(stderr, "Error initializing protocol proto_reddit\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_REDTUBE //////////////////
    if (!init_proto_redtube_struct()) {
        fprintf(stderr, "Error initializing protocol proto_redtube\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_REFERENCE //////////////////
    if (!init_proto_reference_struct()) {
        fprintf(stderr, "Error initializing protocol proto_reference\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RENREN //////////////////
    if (!init_proto_renren_struct()) {
        fprintf(stderr, "Error initializing protocol proto_renren\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ROBLOX //////////////////
    if (!init_proto_roblox_struct()) {
        fprintf(stderr, "Error initializing protocol proto_roblox\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ROVIO //////////////////
    if (!init_proto_rovio_struct()) {
        fprintf(stderr, "Error initializing protocol proto_rovio\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RTP //////////////////
    if (!init_proto_rtp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_rtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RTSP //////////////////
    if (!init_proto_rtsp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_rtsp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SABAHTR //////////////////
    if (!init_proto_sabahtr_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sabahtr\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SAHIBINDEN //////////////////
    if (!init_proto_sahibinden_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sahibinden\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SALESFORCE //////////////////
    if (!init_proto_salesforce_struct()) {
        fprintf(stderr, "Error initializing protocol proto_salesforce\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SALON //////////////////
    if (!init_proto_salon_struct()) {
        fprintf(stderr, "Error initializing protocol proto_salon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCTP //////////////////
    if (!init_proto_sctp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sctp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SEARCHNU //////////////////
    if (!init_proto_searchnu_struct()) {
        fprintf(stderr, "Error initializing protocol proto_searchnu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SEARCH-RESULTS //////////////////
    if (!init_proto_search_results_struct()) {
        fprintf(stderr, "Error initializing protocol proto_search_results\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SEARS //////////////////
    if (!init_proto_sears_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sears\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SECONDLIFE //////////////////
    if (!init_proto_secondlife_struct()) {
        fprintf(stderr, "Error initializing protocol proto_secondlife\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SECURESERVER //////////////////
    if (!init_proto_secureserver_struct()) {
        fprintf(stderr, "Error initializing protocol proto_secureserver\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SFLOW //////////////////
    if (!init_proto_sflow_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sflow\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SHAZAM //////////////////
    if (!init_proto_shazam_struct()) {
        fprintf(stderr, "Error initializing protocol proto_shazam\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SHOUTCAST //////////////////
    if (!init_proto_shoutcast_struct()) {
        fprintf(stderr, "Error initializing protocol proto_shoutcast\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SINA //////////////////
    if (!init_proto_sina_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sina\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SIP //////////////////
    if (!init_proto_sip_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SITEADVISOR //////////////////
    if (!init_proto_siteadvisor_struct()) {
        fprintf(stderr, "Error initializing protocol proto_siteadvisor\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKY //////////////////
    if (!init_proto_sky_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sky\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKYPE //////////////////
    if (!init_proto_skype_struct()) {
        fprintf(stderr, "Error initializing protocol proto_skype\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKYROCK //////////////////
    if (!init_proto_skyrock_struct()) {
        fprintf(stderr, "Error initializing protocol proto_skyrock\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKYSPORTS //////////////////
    if (!init_proto_skysports_struct()) {
        fprintf(stderr, "Error initializing protocol proto_skysports\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SLATE //////////////////
    if (!init_proto_slate_struct()) {
        fprintf(stderr, "Error initializing protocol proto_slate\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SLIDESHARE //////////////////
    if (!init_proto_slideshare_struct()) {
        fprintf(stderr, "Error initializing protocol proto_slideshare\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMB //////////////////
    if (!init_proto_smb_struct()) {
        fprintf(stderr, "Error initializing protocol proto_smb\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMTP //////////////////
    if (!init_proto_smtp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_smtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMTPS //////////////////
    if (!init_proto_smtps_struct()) {
        fprintf(stderr, "Error initializing protocol proto_smtps\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNMP //////////////////
    if (!init_proto_snmp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_snmp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOCRATES //////////////////
    if (!init_proto_socrates_struct()) {
        fprintf(stderr, "Error initializing protocol proto_socrates\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOFTONIC //////////////////
    if (!init_proto_softonic_struct()) {
        fprintf(stderr, "Error initializing protocol proto_softonic\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOGOU //////////////////
    if (!init_proto_sogou_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sogou\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOHU //////////////////
    if (!init_proto_sohu_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sohu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOPCAST //////////////////
    if (!init_proto_sopcast_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sopcast\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOSO //////////////////
    if (!init_proto_soso_struct()) {
        fprintf(stderr, "Error initializing protocol proto_soso\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOULSEEK //////////////////
    if (!init_proto_soulseek_struct()) {
        fprintf(stderr, "Error initializing protocol proto_soulseek\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOUNDCLOUD //////////////////
    if (!init_proto_soundcloud_struct()) {
        fprintf(stderr, "Error initializing protocol proto_soundcloud\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOURGEFORGE //////////////////
    if (!init_proto_sourgeforge_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sourgeforge\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SPIEGEL //////////////////
    if (!init_proto_spiegel_struct()) {
        fprintf(stderr, "Error initializing protocol proto_spiegel\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SPORX //////////////////
    if (!init_proto_sporx_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sporx\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SPOTIFY //////////////////
    if (!init_proto_spotify_struct()) {
        fprintf(stderr, "Error initializing protocol proto_spotify\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SQUIDOO //////////////////
    if (!init_proto_squidoo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_squidoo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SSDP //////////////////
    if (!init_proto_ssdp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ssdp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SSH //////////////////
    if (!init_proto_ssh_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ssh\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SSL //////////////////
    if (!init_proto_ssl_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ssl\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STACK_OVERFLOW //////////////////
    if (!init_proto_stack_overflow_struct()) {
        fprintf(stderr, "Error initializing protocol proto_stack_overflow\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STATCOUNTER //////////////////
    if (!init_proto_statcounter_struct()) {
        fprintf(stderr, "Error initializing protocol proto_statcounter\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STEALTHNET //////////////////
    if (!init_proto_stealthnet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_stealthnet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STEAM //////////////////
    if (!init_proto_steam_struct()) {
        fprintf(stderr, "Error initializing protocol proto_steam\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STUMBLEUPON //////////////////
    if (!init_proto_stumbleupon_struct()) {
        fprintf(stderr, "Error initializing protocol proto_stumbleupon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STUN //////////////////
    if (!init_proto_stun_struct()) {
        fprintf(stderr, "Error initializing protocol proto_stun\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SULEKHA //////////////////
    if (!init_proto_sulekha_struct()) {
        fprintf(stderr, "Error initializing protocol proto_sulekha\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SYSLOG //////////////////
    if (!init_proto_syslog_struct()) {
        fprintf(stderr, "Error initializing protocol proto_syslog\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TAGGED //////////////////
    if (!init_proto_tagged_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tagged\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TAOBAO //////////////////
    if (!init_proto_taobao_struct()) {
        fprintf(stderr, "Error initializing protocol proto_taobao\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TARGET //////////////////
    if (!init_proto_target_struct()) {
        fprintf(stderr, "Error initializing protocol proto_target\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TCO //////////////////
    if (!init_proto_tco_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tco\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TCP //////////////////
    if (!init_proto_tcp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tcp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TDS //////////////////
    if (!init_proto_tds_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tds\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TEAMVIEWER //////////////////
    if (!init_proto_teamviewer_struct()) {
        fprintf(stderr, "Error initializing protocol proto_teamviewer\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TELNET //////////////////
    if (!init_proto_telnet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_telnet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TFTP //////////////////
    if (!init_proto_tftp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tftp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_THEMEFOREST //////////////////
    if (!init_proto_themeforest_struct()) {
        fprintf(stderr, "Error initializing protocol proto_themeforest\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_THE_PIRATE_BAY //////////////////
    if (!init_proto_the_pirate_bay_struct()) {
        fprintf(stderr, "Error initializing protocol proto_the_pirate_bay\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_THUNDER //////////////////
    if (!init_proto_thunder_struct()) {
        fprintf(stderr, "Error initializing protocol proto_thunder\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TIANYA //////////////////
    if (!init_proto_tianya_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tianya\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TLS //////////////////
    if (!init_proto_tls_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tls\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TMALL //////////////////
    if (!init_proto_tmall_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tmall\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TORRENTZ //////////////////
    if (!init_proto_torrentz_struct()) {
        fprintf(stderr, "Error initializing protocol proto_torrentz\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TRUPHONE //////////////////
    if (!init_proto_truphone_struct()) {
        fprintf(stderr, "Error initializing protocol proto_truphone\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TUBE8 //////////////////
    if (!init_proto_tube8_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tube8\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TUDOU //////////////////
    if (!init_proto_tudou_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tudou\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TUENTI //////////////////
    if (!init_proto_tuenti_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tuenti\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TUMBLR //////////////////
    if (!init_proto_tumblr_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tumblr\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TVANTS //////////////////
    if (!init_proto_tvants_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tvants\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TVUPLAYER //////////////////
    if (!init_proto_tvuplayer_struct()) {
        fprintf(stderr, "Error initializing protocol proto_tvuplayer\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TWITTER //////////////////
    if (!init_proto_twitter_struct()) {
        fprintf(stderr, "Error initializing protocol proto_twitter\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UBI //////////////////
    if (!init_proto_ubi_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ubi\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UCOZ //////////////////
    if (!init_proto_ucoz_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ucoz\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UDP //////////////////
    if (!init_proto_udp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_udp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UDPLITE //////////////////
    if (!init_proto_udplite_struct()) {
        fprintf(stderr, "Error initializing protocol proto_udplite\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UOL //////////////////
    if (!init_proto_uol_struct()) {
        fprintf(stderr, "Error initializing protocol proto_uol\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_USDEPARTMENTOFSTATE //////////////////
    if (!init_proto_usdepartmentofstate_struct()) {
        fprintf(stderr, "Error initializing protocol proto_usdepartmentofstate\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_USENET //////////////////
    if (!init_proto_usenet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_usenet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_USTREAM //////////////////
    if (!init_proto_ustream_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ustream\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_APPLICATION_VEOHTV //////////////////
    if (!init_proto_http_application_veohtv_struct()) {
        fprintf(stderr, "Error initializing protocol proto_http_application_veohtv\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VIADEO //////////////////
    if (!init_proto_viadeo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_viadeo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VIBER //////////////////
    if (!init_proto_viber_struct()) {
        fprintf(stderr, "Error initializing protocol proto_viber\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VIMEO //////////////////
    if (!init_proto_vimeo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_vimeo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VK //////////////////
    if (!init_proto_vk_struct()) {
        fprintf(stderr, "Error initializing protocol proto_vk\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VKONTAKTE //////////////////
    if (!init_proto_vkontakte_struct()) {
        fprintf(stderr, "Error initializing protocol proto_vkontakte\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VNC //////////////////
    if (!init_proto_vnc_struct()) {
        fprintf(stderr, "Error initializing protocol proto_vnc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WALMART //////////////////
    if (!init_proto_walmart_struct()) {
        fprintf(stderr, "Error initializing protocol proto_walmart\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WARRIORFORUM //////////////////
    if (!init_proto_warriorforum_struct()) {
        fprintf(stderr, "Error initializing protocol proto_warriorforum\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WAYN //////////////////
    if (!init_proto_wayn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wayn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WEATHER //////////////////
    if (!init_proto_weather_struct()) {
        fprintf(stderr, "Error initializing protocol proto_weather\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WEBEX //////////////////
    if (!init_proto_webex_struct()) {
        fprintf(stderr, "Error initializing protocol proto_webex\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WEEKLYSTANDARD //////////////////
    if (!init_proto_weeklystandard_struct()) {
        fprintf(stderr, "Error initializing protocol proto_weeklystandard\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WEIBO //////////////////
    if (!init_proto_weibo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_weibo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WELLSFARGO //////////////////
    if (!init_proto_wellsfargo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wellsfargo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WHATSAPP //////////////////
    if (!init_proto_whatsapp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_whatsapp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WIGETMEDIA //////////////////
    if (!init_proto_wigetmedia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wigetmedia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WIKIA //////////////////
    if (!init_proto_wikia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wikia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WIKIMEDIA //////////////////
    if (!init_proto_wikimedia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wikimedia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WIKIPEDIA //////////////////
    if (!init_proto_wikipedia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wikipedia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WILLIAMHILL //////////////////
    if (!init_proto_williamhill_struct()) {
        fprintf(stderr, "Error initializing protocol proto_williamhill\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WINDOWSLIVE //////////////////
    if (!init_proto_windowslive_struct()) {
        fprintf(stderr, "Error initializing protocol proto_windowslive\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WINDOWSMEDIA //////////////////
    if (!init_proto_windowsmedia_struct()) {
        fprintf(stderr, "Error initializing protocol proto_windowsmedia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WINMX //////////////////
    if (!init_proto_winmx_struct()) {
        fprintf(stderr, "Error initializing protocol proto_winmx\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WINUPDATE //////////////////
    if (!init_proto_winupdate_struct()) {
        fprintf(stderr, "Error initializing protocol proto_winupdate\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WORLD_OF_KUNG_FU //////////////////
    if (!init_proto_world_of_kung_fu_struct()) {
        fprintf(stderr, "Error initializing protocol proto_world_of_kung_fu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WORDPRESS_ORG //////////////////
    if (!init_proto_wordpress_org_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wordpress_org\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WARCRAFT3 //////////////////
    if (!init_proto_warcraft3_struct()) {
        fprintf(stderr, "Error initializing protocol proto_warcraft3\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WORLDOFWARCRAFT //////////////////
    if (!init_proto_worldofwarcraft_struct()) {
        fprintf(stderr, "Error initializing protocol proto_worldofwarcraft\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WOWHEAD //////////////////
    if (!init_proto_wowhead_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wowhead\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WWE //////////////////
    if (!init_proto_wwe_struct()) {
        fprintf(stderr, "Error initializing protocol proto_wwe\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XBOX //////////////////
    if (!init_proto_xbox_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xbox\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XDMCP //////////////////
    if (!init_proto_xdmcp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xdmcp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XHAMSTER //////////////////
    if (!init_proto_xhamster_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xhamster\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XING //////////////////
    if (!init_proto_xing_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xing\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XINHUANET //////////////////
    if (!init_proto_xinhuanet_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xinhuanet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNXX //////////////////
    if (!init_proto_xnxx_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xnxx\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XVIDEOS //////////////////
    if (!init_proto_xvideos_struct()) {
        fprintf(stderr, "Error initializing protocol proto_xvideos\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YAHOO //////////////////
    if (!init_proto_yahoo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_yahoo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YAHOOGAMES //////////////////
    if (!init_proto_yahoogames_struct()) {
        fprintf(stderr, "Error initializing protocol proto_yahoogames\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YAHOOMAIL //////////////////
    if (!init_proto_yahoomail_struct()) {
        fprintf(stderr, "Error initializing protocol proto_yahoomail\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YANDEX //////////////////
    if (!init_proto_yandex_struct()) {
        fprintf(stderr, "Error initializing protocol proto_yandex\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YELP //////////////////
    if (!init_proto_yelp_struct()) {
        fprintf(stderr, "Error initializing protocol proto_yelp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YOUKU //////////////////
    if (!init_proto_youku_struct()) {
        fprintf(stderr, "Error initializing protocol proto_youku\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YOUPORN //////////////////
    if (!init_proto_youporn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_youporn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_YOUTUBE //////////////////
    if (!init_proto_youtube_struct()) {
        fprintf(stderr, "Error initializing protocol proto_youtube\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZAPPOS //////////////////
    if (!init_proto_zappos_struct()) {
        fprintf(stderr, "Error initializing protocol proto_zappos\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZATTOO //////////////////
    if (!init_proto_zattoo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_zattoo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZEDO //////////////////
    if (!init_proto_zedo_struct()) {
        fprintf(stderr, "Error initializing protocol proto_zedo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZOL //////////////////
    if (!init_proto_zol_struct()) {
        fprintf(stderr, "Error initializing protocol proto_zol\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZYNGA //////////////////
    if (!init_proto_zynga_struct()) {
        fprintf(stderr, "Error initializing protocol proto_zynga\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_3PC //////////////////
    if (!init_proto_3pc_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_3pc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Any_0hop //////////////////
    if (!init_proto_any_0hop_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_any_0hop\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Any_dfs //////////////////
    if (!init_proto_any_dfs_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_any_dfs\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Any_hip //////////////////
    if (!init_proto_any_hip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_any_hip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Any_local //////////////////
    if (!init_proto_any_local_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_any_local\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Any_pes //////////////////
    if (!init_proto_any_pes_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_any_pes\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARGUS //////////////////
    if (!init_proto_argus_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_argus\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARIS //////////////////
    if (!init_proto_aris_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_aris\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AX_25 //////////////////
    if (!init_proto_ax_25_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ax_25\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BBN_RCC_MON //////////////////
    if (!init_proto_bbn_rcc_mon_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_bbn_rcc_mon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BNA //////////////////
    if (!init_proto_bna_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_bna\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BR_SAT_MON //////////////////
    if (!init_proto_br_sat_mon_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_br_sat_mon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CBT //////////////////
    if (!init_proto_cbt_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cbt\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CFTP //////////////////
    if (!init_proto_cftp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cftp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHAOS //////////////////
    if (!init_proto_chaos_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_chaos\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Compaq_Peer //////////////////
    if (!init_proto_compaq_peer_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_compaq_peer\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CPHB //////////////////
    if (!init_proto_cphb_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cphb\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CPNX //////////////////
    if (!init_proto_cpnx_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cpnx\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CRTP //////////////////
    if (!init_proto_crtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_crtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CRUDP //////////////////
    if (!init_proto_crudp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_crudp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DCCP //////////////////
    if (!init_proto_dccp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_dccp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DCN_MEAS //////////////////
    if (!init_proto_dcn_meas_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_dcn_meas\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DDP //////////////////
    if (!init_proto_ddp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ddp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DDX //////////////////
    if (!init_proto_ddx_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ddx\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DGP //////////////////
    if (!init_proto_dgp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_dgp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EIGRP //////////////////
    if (!init_proto_eigrp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_eigrp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EMCON //////////////////
    if (!init_proto_emcon_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_emcon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENCAP //////////////////
    if (!init_proto_encap_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_encap\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ETHERIP //////////////////
    if (!init_proto_etherip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_etherip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FC //////////////////
    if (!init_proto_fc_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_fc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FIRE //////////////////
    if (!init_proto_fire_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_fire\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GGP //////////////////
    if (!init_proto_ggp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ggp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GMTP //////////////////
    if (!init_proto_gmtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_gmtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HIP //////////////////
    if (!init_proto_hip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_hip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HMP //////////////////
    if (!init_proto_hmp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_hmp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_I_NLSP //////////////////
    if (!init_proto_i_nlsp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_i_nlsp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IATP //////////////////
    if (!init_proto_iatp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_iatp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDPR //////////////////
    if (!init_proto_idpr_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_idpr\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDPR_CMTP //////////////////
    if (!init_proto_idpr_cmtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_idpr_cmtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDRP //////////////////
    if (!init_proto_idrp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_idrp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IFMP //////////////////
    if (!init_proto_ifmp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ifmp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IGP //////////////////
    if (!init_proto_igp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_igp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IL //////////////////
    if (!init_proto_il_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_il\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPComp //////////////////
    if (!init_proto_ipcomp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ipcomp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPCV //////////////////
    if (!init_proto_ipcv_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ipcv\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPLT //////////////////
    if (!init_proto_iplt_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_iplt\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPPC //////////////////
    if (!init_proto_ippc_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ippc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPTM //////////////////
    if (!init_proto_iptm_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_iptm\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPX_in_IP //////////////////
    if (!init_proto_ipx_in_ip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ipx_in_ip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRTP //////////////////
    if (!init_proto_irtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_irtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IS_IS //////////////////
    if (!init_proto_is_is_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_is_is\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISO_IP //////////////////
    if (!init_proto_iso_ip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_iso_ip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISO_TP4 //////////////////
    if (!init_proto_iso_tp4_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_iso_tp4\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_KRYPTOLAN //////////////////
    if (!init_proto_kryptolan_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_kryptolan\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LARP //////////////////
    if (!init_proto_larp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_larp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEAF_1 //////////////////
    if (!init_proto_leaf_1_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_leaf_1\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEAF_2 //////////////////
    if (!init_proto_leaf_2_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_leaf_2\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MERIT_INP //////////////////
    if (!init_proto_merit_inp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_merit_inp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MFE_NSP //////////////////
    if (!init_proto_mfe_nsp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mfe_nsp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MHRP //////////////////
    if (!init_proto_mhrp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mhrp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MICP //////////////////
    if (!init_proto_micp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_micp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MOBILE //////////////////
    if (!init_proto_mobile_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mobile\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Mobility_Header //////////////////
    if (!init_proto_mobility_header_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mobility_header\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPLS_in_IP //////////////////
    if (!init_proto_mpls_in_ip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mpls_in_ip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MTP //////////////////
    if (!init_proto_mtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MUX //////////////////
    if (!init_proto_mux_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mux\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NARP //////////////////
    if (!init_proto_narp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_narp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETBLT //////////////////
    if (!init_proto_netblt_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_netblt\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NSFNET_IGP //////////////////
    if (!init_proto_nsfnet_igp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_nsfnet_igp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NVP_II //////////////////
    if (!init_proto_nvp_ii_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_nvp_ii\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PGM //////////////////
    if (!init_proto_pgm_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_pgm\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PIM //////////////////
    if (!init_proto_pim_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_pim\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PIPE //////////////////
    if (!init_proto_pipe_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_pipe\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PNNI //////////////////
    if (!init_proto_pnni_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_pnni\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PRM //////////////////
    if (!init_proto_prm_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_prm\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PTP //////////////////
    if (!init_proto_ptp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ptp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PUP //////////////////
    if (!init_proto_pup_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_pup\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PVP //////////////////
    if (!init_proto_pvp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_pvp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_QNX //////////////////
    if (!init_proto_qnx_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_qnx\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RSVP //////////////////
    if (!init_proto_rsvp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_rsvp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RSVP_E2E_IGNORE //////////////////
    if (!init_proto_rsvp_e2e_ignore_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_rsvp_e2e_ignore\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RVD //////////////////
    if (!init_proto_rvd_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_rvd\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SAT_EXPAK //////////////////
    if (!init_proto_sat_expak_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sat_expak\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SAT_MON //////////////////
    if (!init_proto_sat_mon_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sat_mon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCC_SP //////////////////
    if (!init_proto_scc_sp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_scc_sp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCPS //////////////////
    if (!init_proto_scps_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_scps\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SDRP //////////////////
    if (!init_proto_sdrp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sdrp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SECURE_VMTP //////////////////
    if (!init_proto_secure_vmtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_secure_vmtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Shim6 //////////////////
    if (!init_proto_shim6_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_shim6\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKIP //////////////////
    if (!init_proto_skip_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_skip\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SM //////////////////
    if (!init_proto_sm_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sm\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMP //////////////////
    if (!init_proto_smp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_smp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNP //////////////////
    if (!init_proto_snp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_snp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_Sprite_RPC //////////////////
    if (!init_proto_sprite_rpc_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sprite_rpc\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SPS //////////////////
    if (!init_proto_sps_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sps\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SRP //////////////////
    if (!init_proto_srp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_srp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SSCOPMCE //////////////////
    if (!init_proto_sscopmce_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sscopmce\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ST //////////////////
    if (!init_proto_st_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_st\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_STP //////////////////
    if (!init_proto_stp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_stp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUN_ND //////////////////
    if (!init_proto_sun_nd_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sun_nd\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SWIPE //////////////////
    if (!init_proto_swipe_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_swipe\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TCF //////////////////
    if (!init_proto_tcf_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_tcf\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TLSP //////////////////
    if (!init_proto_tlsp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_tlsp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TP_pp //////////////////
    if (!init_proto_tp_pp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_tp_pp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TRUNK_1 //////////////////
    if (!init_proto_trunk_1_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_trunk_1\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TRUNK_2 //////////////////
    if (!init_proto_trunk_2_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_trunk_2\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_UTI //////////////////
    if (!init_proto_uti_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_uti\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VINES //////////////////
    if (!init_proto_vines_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_vines\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VISA //////////////////
    if (!init_proto_visa_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_visa\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VMTP //////////////////
    if (!init_proto_vmtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_vmtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VRRP //////////////////
    if (!init_proto_vrrp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_vrrp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WB_EXPAK //////////////////
    if (!init_proto_wb_expak_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_wb_expak\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WB_MON //////////////////
    if (!init_proto_wb_mon_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_wb_mon\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WSN //////////////////
    if (!init_proto_wsn_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_wsn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNET //////////////////
    if (!init_proto_xnet_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_xnet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNS_IDP //////////////////
    if (!init_proto_xns_idp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_xns_idp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_XTP //////////////////
    if (!init_proto_xtp_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_xtp\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BUZZNET //////////////////
    if (!init_proto_buzznet_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_buzznet\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMEDY //////////////////
    if (!init_proto_comedy_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_comedy\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RAMBLER //////////////////
    if (!init_proto_rambler_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_rambler\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMUGMUG //////////////////
    if (!init_proto_smugmug_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_smugmug\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARCHIEVE //////////////////
    if (!init_proto_archieve_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_archieve\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CITYNEWS //////////////////
    if (!init_proto_citynews_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_citynews\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCIENCESTAGE //////////////////
    if (!init_proto_sciencestage_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sciencestage\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ONEWORLD //////////////////
    if (!init_proto_oneworld_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_oneworld\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DISQUS //////////////////
    if (!init_proto_disqus_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_disqus\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLOGCU //////////////////
    if (!init_proto_blogcu_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_blogcu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EKOLEY //////////////////
    if (!init_proto_ekoley_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ekoley\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_500PX //////////////////
    if (!init_proto_500px_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_500px\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FOTKI //////////////////
    if (!init_proto_fotki_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_fotki\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FOTOLOG //////////////////
    if (!init_proto_fotolog_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_fotolog\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_JALBUM //////////////////
    if (!init_proto_jalbum_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_jalbum\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LOCKERZ //////////////////
    if (!init_proto_lockerz_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_lockerz\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_PANORAMIO //////////////////
    if (!init_proto_panoramio_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_panoramio\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNAPFISH //////////////////
    if (!init_proto_snapfish_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_snapfish\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WEBSHOTS //////////////////
    if (!init_proto_webshots_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_webshots\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MEGA //////////////////
    if (!init_proto_mega_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mega\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VIDOOSH //////////////////
    if (!init_proto_vidoosh_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_vidoosh\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AFREECA //////////////////
    if (!init_proto_afreeca_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_afreeca\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WILDSCREEN //////////////////
    if (!init_proto_wildscreen_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_wildscreen\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLOGTV //////////////////
    if (!init_proto_blogtv_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_blogtv\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HULU //////////////////
    if (!init_proto_hulu_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_hulu\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MEVIO //////////////////
    if (!init_proto_mevio_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mevio\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVESTREAM //////////////////
    if (!init_proto_livestream_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_livestream\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIVELEAK //////////////////
    if (!init_proto_liveleak_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_liveleak\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEEZER //////////////////
    if (!init_proto_deezer_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_deezer\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLIPTV //////////////////
    if (!init_proto_bliptv_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_bliptv\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BREAK //////////////////
    if (!init_proto_break_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_break\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CITYTV //////////////////
    if (!init_proto_citytv_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_citytv\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMEDYCENTRAL //////////////////
    if (!init_proto_comedycentral_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_comedycentral\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENGAGEMEDIA //////////////////
    if (!init_proto_engagemedia_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_engagemedia\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCREENJUNKIES //////////////////
    if (!init_proto_screenjunkies_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_screenjunkies\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RUTUBE //////////////////
    if (!init_proto_rutube_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_rutube\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SEVENLOAD //////////////////
    if (!init_proto_sevenload_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_sevenload\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MUBI //////////////////
    if (!init_proto_mubi_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mubi\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_IZLESENE //////////////////
    if (!init_proto_izlesene_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_izlesene\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VIDEO_HOSTING //////////////////
    if (!init_proto_video_hosting_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_video_hosting\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BOX //////////////////
    if (!init_proto_box_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_box\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKYDRIVE //////////////////
    if (!init_proto_skydrive_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_skydrive\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_7DIGITAL //////////////////
    if (!init_proto_7digital_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_7digital\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CLOUDFRONT //////////////////
    if (!init_proto_cloudfront_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cloudfront\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_TANGO //////////////////
    if (!init_proto_tango_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_tango\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_WECHAT //////////////////
    if (!init_proto_wechat_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_wechat\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LINE //////////////////
    if (!init_proto_line_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_line\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLOOMBERG //////////////////
    if (!init_proto_bloomberg_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_bloomberg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSCDN //////////////////
    if (!init_proto_mscdn_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_mscdn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_AKAMAI //////////////////
    if (!init_proto_akamai_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_akamai\n Exiting\n");
        exit(0);
    }
    ////////////////////////////////////////////
    /////////// INITILIZING PROTO_YAHOOMSG //////////////////
    if (!init_proto_yahoomsg_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_yahoomsg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BITGRAVITY //////////////////
    if (!init_proto_bitgravity_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_bitgravity\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CACHEFLY //////////////////
    if (!init_proto_cachefly_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cachefly\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CDN77 //////////////////
    if (!init_proto_cdn77_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cdn77\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CDNETWORKS //////////////////
    if (!init_proto_cdnetworks_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cdnetworks\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHINACACHE //////////////////
    if (!init_proto_chinacache_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_chinacache\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_COTENDO //////////////////
    if (!init_proto_cotendo_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_cotendo\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_EDGECAST //////////////////
    if (!init_proto_edgecast_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_edgecast\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FASTLY //////////////////
    if (!init_proto_fastly_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_fastly\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_HIGHWINDS //////////////////
    if (!init_proto_highwinds_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_highwinds\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_INTERNAP //////////////////
    if (!init_proto_internap_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_internap\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEVEL3 //////////////////
    if (!init_proto_level3_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_level3\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_LIMELIGHT //////////////////
    if (!init_proto_limelight_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_limelight\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAXCDN //////////////////
    if (!init_proto_maxcdn_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_maxcdn\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETDNA //////////////////
    if (!init_proto_netdna_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_netdna\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_VOXEL //////////////////
    if (!init_proto_voxel_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_voxel\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_RACKSPACE //////////////////
    if (!init_proto_rackspace_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_rackspace\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GAMEFORGE //////////////////
    if (!init_proto_gameforge_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_gameforge\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_METIN2 //////////////////
    if (!init_proto_metin2_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_metin2\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_OGAME //////////////////
    if (!init_proto_ogame_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_ogame\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_BATTLEKNIGHT //////////////////
    if (!init_proto_battleknight_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_battleknight\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_4STORY //////////////////
    if (!init_proto_4story_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_4story\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_FBMSG //////////////////
    if (!init_proto_fbmsg_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_fbmsg\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GCM //////////////////
    if (!init_proto_gcm_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_gcm\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////

    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_GCM //////////////////
    if (!init_proto_sll_struct()) {
        fprintf(stderr, "Error initializing protocol PROTO_SLL\n Exiting\n");
        exit(0);
    }

    /////////// INITILIZING PROTO_QUIC //////////////////
    if (!init_proto_quic_struct()) {
        fprintf(stderr, "Error initializing protocol proto_quic\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ORACLE //////////////////
    if (!init_proto_oracle_struct()) {
        fprintf(stderr, "Error initializing protocol proto_oracle\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_ORACLE //////////////////
    if (!init_proto_redis_struct()) {
        fprintf(stderr, "Error initializing protocol proto_redis\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
       /////////// INITILIZING PROTO_ORACLE //////////////////
    if (!init_proto_vmware_struct()) {
        fprintf(stderr, "Error initializing protocol proto_vmware\n Exiting\n");
        exit(0);
    }
    /////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////END OF GENERATED CODE ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////START OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////
    /***
        
        CLASSIFY PROTOCOL OVER TCP PROTOCOL

    ***/

    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http, 20);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ssl, 20);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_stun_tcp, 30);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rtp_tcp, 50); //Check STUN before RTP
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rdp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_sip, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_bittorrent_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_edonkey, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_fasttrack, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_gnutella, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_winmx, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_directconnect_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_msn_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_yahoo_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_oscar, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_applejuice, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_soulseek, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_irc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_jabber, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pop, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_imap, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_smtp, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ndn, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ndn_http, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_usenet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dns, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_filetopia, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_manolito_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_imesh_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mms, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pando, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tvants_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_sopcast_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tvuplayer_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ppstream_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pplive_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_gadugadu, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_zattoo_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_qq_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_feidian_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ssh, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_popo, 50); //BW: TODO: check this out
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_thunder_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_vnc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_teamviewer_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_i23v5, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_socrates_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_steam, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_xbox, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http_application_activesync, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_smb, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_telnet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_nfs, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_worldofwarcraft, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_flash, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_postgres, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mysql, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_bgp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_secondlife_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pcanywhere, 50); //BW: TODO: The classification of PCANYWHERE seems to be for UDP only, check this out
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_icecast, 50); //BW: TODO: Check out the classification --- dependence on http
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_shoutcast, 50); //BW: TODO: Check out the classification --- dependence on http
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_veohtv_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_kerberos, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_openft, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_syslog, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tds, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_direct_download_link, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_netbios_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ipp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ldap, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_warcraft3, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_xdmcp_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mssql, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pptp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_stealthnet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_meebo, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_afp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_aimini_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_florensia_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_maplestory, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dofus, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_world_of_kung_fu, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_fiesta, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_crossfire_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_guildwars, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_skype_tcp, 60);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_citrix, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dcerpc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_spotify, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_oracle, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_redis, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp_control, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp_data, 50);
    /***
        
        CLASSIFY PROTOCOL OVER UDP PROTOCOL

    ***/
#ifndef LIGHTSDK
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_stun_udp, 30);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_rtp_udp, 50); //Check STUN before RTP
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sip, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_bittorrent_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_edonkey, 50); //BW: TODO: Edonkey classification seems limited to TCP! Check this out
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gnutella, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_directconnect_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_msn_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_yahoo_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_oscar, 50); //BW: TODO: the calssification of oscar seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_jabber, 50); //BW: TODO: the calssification of jabber seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ndn, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ndn_http, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dns, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_manolito_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_imesh_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pando, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tvants_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sopcast_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tvuplayer_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ppstream_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pplive_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_iax, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_mgcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gadugadu, 50); //BW: TODO: the calssification of gadugadu seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_zattoo_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_qq_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_feidian_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_popo, 50); //BW: TODO: check this out
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_thunder_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_teamviewer_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dhcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_socrates_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_halflife2, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_xbox, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ntp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_nfs, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ssdp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_quake, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_battlefield, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_secondlife_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pcanywhere, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_snmp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_kontiki, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_veohtv_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_syslog, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_netbios_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_mdns, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ipp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ldap, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_warcraft3, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_xdmcp_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tftp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dhcpv6, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_aimini_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_florensia_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_crossfire_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_armagetron, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dropbox_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_skype_udp, 60);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_radius, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_netflow, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sflow, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_quic, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_vmware, 50);
#endif    
    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////////END OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    return retval;
}

