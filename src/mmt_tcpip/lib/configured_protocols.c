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
    /////////// INITILIZING PROTO_360BUY //////////////////
    if (!init_proto_360buy_struct()) {
        fprintf(stderr, "Error initializing protocol proto_360buy\n Exiting\n");
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
    /////////////////////////////////////////////
    /////////// INITILIZING PROTO_NDN //////////////////
    if (!init_proto_ndn_struct()) {
        fprintf(stderr, "Error initializing protocol proto_ndn\n Exiting\n");
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
    if (!init_proto_huffington_post_struct()) {
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
    /////////// INITILIZING PROTO_INTERNET_MOVIE_DATABASE //////////////////
    if (!init_proto_internet_movie_database_struct()) {
        fprintf(stderr, "Error initializing protocol proto_internet_movie_database\n Exiting\n");
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
    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TCPMUX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tcpmux_struct()){
         fprintf(stderr, "Error initializing protocol proto_tcpmux");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMPRESSNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_compressnet_struct()){
         fprintf(stderr, "Error initializing protocol proto_compressnet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RJE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rje_struct()){
         fprintf(stderr, "Error initializing protocol proto_rje");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ECHO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_echo_struct()){
         fprintf(stderr, "Error initializing protocol proto_echo");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DISCARD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_discard_struct()){
         fprintf(stderr, "Error initializing protocol proto_discard");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SYSTAT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_systat_struct()){
         fprintf(stderr, "Error initializing protocol proto_systat");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DAYTIME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_daytime_struct()){
         fprintf(stderr, "Error initializing protocol proto_daytime");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QOTD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_qotd_struct()){
         fprintf(stderr, "Error initializing protocol proto_qotd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_msp_struct()){
         fprintf(stderr, "Error initializing protocol proto_msp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHARGEN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_chargen_struct()){
         fprintf(stderr, "Error initializing protocol proto_chargen");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FTP_DATA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ftp_data_struct()){
         fprintf(stderr, "Error initializing protocol proto_ftp_data");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NSW_FE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nsw_fe_struct()){
         fprintf(stderr, "Error initializing protocol proto_nsw_fe");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSG_ICP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_msg_icp_struct()){
         fprintf(stderr, "Error initializing protocol proto_msg_icp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSG_AUTH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_msg_auth_struct()){
         fprintf(stderr, "Error initializing protocol proto_msg_auth");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DSP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dsp_struct()){
         fprintf(stderr, "Error initializing protocol proto_dsp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TIME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_time_struct()){
         fprintf(stderr, "Error initializing protocol proto_time");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rap_struct()){
         fprintf(stderr, "Error initializing protocol proto_rap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RLP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rlp_struct()){
         fprintf(stderr, "Error initializing protocol proto_rlp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GRAPHICS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_graphics_struct()){
         fprintf(stderr, "Error initializing protocol proto_graphics");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NAME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_name_struct()){
         fprintf(stderr, "Error initializing protocol proto_name");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NAMESERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nameserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_nameserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NICNAME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nicname_struct()){
         fprintf(stderr, "Error initializing protocol proto_nicname");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPM_FLAGS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mpm_flags_struct()){
         fprintf(stderr, "Error initializing protocol proto_mpm_flags");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mpm_struct()){
         fprintf(stderr, "Error initializing protocol proto_mpm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPM_SND //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mpm_snd_struct()){
         fprintf(stderr, "Error initializing protocol proto_mpm_snd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NI_FTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ni_ftp_struct()){
         fprintf(stderr, "Error initializing protocol proto_ni_ftp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AUDITD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_auditd_struct()){
         fprintf(stderr, "Error initializing protocol proto_auditd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TACACS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tacacs_struct()){
         fprintf(stderr, "Error initializing protocol proto_tacacs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RE_MAIL_CK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_re_mail_ck_struct()){
         fprintf(stderr, "Error initializing protocol proto_re_mail_ck");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNS_TIME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xns_time_struct()){
         fprintf(stderr, "Error initializing protocol proto_xns_time");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DOMAIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_domain_struct()){
         fprintf(stderr, "Error initializing protocol proto_domain");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNS_CH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xns_ch_struct()){
         fprintf(stderr, "Error initializing protocol proto_xns_ch");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISI_GL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_isi_gl_struct()){
         fprintf(stderr, "Error initializing protocol proto_isi_gl");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNS_AUTH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xns_auth_struct()){
         fprintf(stderr, "Error initializing protocol proto_xns_auth");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNS_MAIL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xns_mail_struct()){
         fprintf(stderr, "Error initializing protocol proto_xns_mail");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NI_MAIL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ni_mail_struct()){
         fprintf(stderr, "Error initializing protocol proto_ni_mail");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_acas_struct()){
         fprintf(stderr, "Error initializing protocol proto_acas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WHOISPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_whoispp_struct()){
         fprintf(stderr, "Error initializing protocol proto_whoispp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WHOIS__ //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_whois___struct()){
         fprintf(stderr, "Error initializing protocol proto_whois__");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COVIA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_covia_struct()){
         fprintf(stderr, "Error initializing protocol proto_covia");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TACACS_DS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tacacs_ds_struct()){
         fprintf(stderr, "Error initializing protocol proto_tacacs_ds");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SQL_NET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sql_net_struct()){
         fprintf(stderr, "Error initializing protocol proto_sql_net");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SQLNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sqlnet_struct()){
         fprintf(stderr, "Error initializing protocol proto_sqlnet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BOOTPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bootps_struct()){
         fprintf(stderr, "Error initializing protocol proto_bootps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BOOTPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bootpc_struct()){
         fprintf(stderr, "Error initializing protocol proto_bootpc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GOPHER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gopher_struct()){
         fprintf(stderr, "Error initializing protocol proto_gopher");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETRJS_1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netrjs_1_struct()){
         fprintf(stderr, "Error initializing protocol proto_netrjs_1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETRJS_2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netrjs_2_struct()){
         fprintf(stderr, "Error initializing protocol proto_netrjs_2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETRJS_3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netrjs_3_struct()){
         fprintf(stderr, "Error initializing protocol proto_netrjs_3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETRJS_4 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netrjs_4_struct()){
         fprintf(stderr, "Error initializing protocol proto_netrjs_4");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEOS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_deos_struct()){
         fprintf(stderr, "Error initializing protocol proto_deos");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VETTCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vettcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_vettcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FINGER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_finger_struct()){
         fprintf(stderr, "Error initializing protocol proto_finger");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WWW //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_www_struct()){
         fprintf(stderr, "Error initializing protocol proto_www");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WWW_HTTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_www_http_struct()){
         fprintf(stderr, "Error initializing protocol proto_www_http");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XFER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xfer_struct()){
         fprintf(stderr, "Error initializing protocol proto_xfer");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MIT_ML_DEV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mit_ml_dev_struct()){
         fprintf(stderr, "Error initializing protocol proto_mit_ml_dev");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CTF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ctf_struct()){
         fprintf(stderr, "Error initializing protocol proto_ctf");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MFCOBOL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mfcobol_struct()){
         fprintf(stderr, "Error initializing protocol proto_mfcobol");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SU_MIT_TG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_su_mit_tg_struct()){
         fprintf(stderr, "Error initializing protocol proto_su_mit_tg");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PORT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_port_struct()){
         fprintf(stderr, "Error initializing protocol proto_port");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DNSIX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dnsix_struct()){
         fprintf(stderr, "Error initializing protocol proto_dnsix");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MIT_DOV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mit_dov_struct()){
         fprintf(stderr, "Error initializing protocol proto_mit_dov");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_npp_struct()){
         fprintf(stderr, "Error initializing protocol proto_npp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_dcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OBJCALL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_objcall_struct()){
         fprintf(stderr, "Error initializing protocol proto_objcall");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUPDUP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_supdup_struct()){
         fprintf(stderr, "Error initializing protocol proto_supdup");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DIXIE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dixie_struct()){
         fprintf(stderr, "Error initializing protocol proto_dixie");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SWIFT_RVF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_swift_rvf_struct()){
         fprintf(stderr, "Error initializing protocol proto_swift_rvf");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TACNEWS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tacnews_struct()){
         fprintf(stderr, "Error initializing protocol proto_tacnews");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_METAGRAM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_metagram_struct()){
         fprintf(stderr, "Error initializing protocol proto_metagram");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HOSTNAME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hostname_struct()){
         fprintf(stderr, "Error initializing protocol proto_hostname");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISO_TSAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iso_tsap_struct()){
         fprintf(stderr, "Error initializing protocol proto_iso_tsap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GPPITNP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gppitnp_struct()){
         fprintf(stderr, "Error initializing protocol proto_gppitnp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACR_NEMA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_acr_nema_struct()){
         fprintf(stderr, "Error initializing protocol proto_acr_nema");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CSO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cso_struct()){
         fprintf(stderr, "Error initializing protocol proto_cso");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CSNET_NS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_csnet_ns_struct()){
         fprintf(stderr, "Error initializing protocol proto_csnet_ns");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_3COM_TSMUX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_3com_tsmux_struct()){
         fprintf(stderr, "Error initializing protocol proto_3com_tsmux");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RTELNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rtelnet_struct()){
         fprintf(stderr, "Error initializing protocol proto_rtelnet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNAGAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_snagas_struct()){
         fprintf(stderr, "Error initializing protocol proto_snagas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_POP2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pop2_struct()){
         fprintf(stderr, "Error initializing protocol proto_pop2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_POP3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pop3_struct()){
         fprintf(stderr, "Error initializing protocol proto_pop3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUNRPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sunrpc_struct()){
         fprintf(stderr, "Error initializing protocol proto_sunrpc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MCIDAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mcidas_struct()){
         fprintf(stderr, "Error initializing protocol proto_mcidas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ident_struct()){
         fprintf(stderr, "Error initializing protocol proto_ident");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AUTH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_auth_struct()){
         fprintf(stderr, "Error initializing protocol proto_auth");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SFTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sftp_struct()){
         fprintf(stderr, "Error initializing protocol proto_sftp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ANSANOTIFY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ansanotify_struct()){
         fprintf(stderr, "Error initializing protocol proto_ansanotify");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UUCP_PATH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uucp_path_struct()){
         fprintf(stderr, "Error initializing protocol proto_uucp_path");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SQLSERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sqlserv_struct()){
         fprintf(stderr, "Error initializing protocol proto_sqlserv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NNTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nntp_struct()){
         fprintf(stderr, "Error initializing protocol proto_nntp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CFDPTKT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cfdptkt_struct()){
         fprintf(stderr, "Error initializing protocol proto_cfdptkt");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ERPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_erpc_struct()){
         fprintf(stderr, "Error initializing protocol proto_erpc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMAKYNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smakynet_struct()){
         fprintf(stderr, "Error initializing protocol proto_smakynet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ANSATRADER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ansatrader_struct()){
         fprintf(stderr, "Error initializing protocol proto_ansatrader");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LOCUS_MAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_locus_map_struct()){
         fprintf(stderr, "Error initializing protocol proto_locus_map");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NXEDIT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nxedit_struct()){
         fprintf(stderr, "Error initializing protocol proto_nxedit");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LOCUS_CON //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_locus_con_struct()){
         fprintf(stderr, "Error initializing protocol proto_locus_con");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GSS_XLICEN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gss_xlicen_struct()){
         fprintf(stderr, "Error initializing protocol proto_gss_xlicen");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PWDGEN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pwdgen_struct()){
         fprintf(stderr, "Error initializing protocol proto_pwdgen");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CISCO_FNA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cisco_fna_struct()){
         fprintf(stderr, "Error initializing protocol proto_cisco_fna");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CISCO_TNA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cisco_tna_struct()){
         fprintf(stderr, "Error initializing protocol proto_cisco_tna");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CISCO_SYS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cisco_sys_struct()){
         fprintf(stderr, "Error initializing protocol proto_cisco_sys");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_STATSRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_statsrv_struct()){
         fprintf(stderr, "Error initializing protocol proto_statsrv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_INGRES_NET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ingres_net_struct()){
         fprintf(stderr, "Error initializing protocol proto_ingres_net");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EPMAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_epmap_struct()){
         fprintf(stderr, "Error initializing protocol proto_epmap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PROFILE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_profile_struct()){
         fprintf(stderr, "Error initializing protocol proto_profile");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETBIOS_NS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netbios_ns_struct()){
         fprintf(stderr, "Error initializing protocol proto_netbios_ns");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETBIOS_DGM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netbios_dgm_struct()){
         fprintf(stderr, "Error initializing protocol proto_netbios_dgm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETBIOS_SSN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netbios_ssn_struct()){
         fprintf(stderr, "Error initializing protocol proto_netbios_ssn");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EMFIS_DATA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_emfis_data_struct()){
         fprintf(stderr, "Error initializing protocol proto_emfis_data");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EMFIS_CNTL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_emfis_cntl_struct()){
         fprintf(stderr, "Error initializing protocol proto_emfis_cntl");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BL_IDM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bl_idm_struct()){
         fprintf(stderr, "Error initializing protocol proto_bl_idm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UMA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uma_struct()){
         fprintf(stderr, "Error initializing protocol proto_uma");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UAAC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uaac_struct()){
         fprintf(stderr, "Error initializing protocol proto_uaac");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISO_TP0 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iso_tp0_struct()){
         fprintf(stderr, "Error initializing protocol proto_iso_tp0");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_JARGON //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_jargon_struct()){
         fprintf(stderr, "Error initializing protocol proto_jargon");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AED_512 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_aed_512_struct()){
         fprintf(stderr, "Error initializing protocol proto_aed_512");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HEMS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hems_struct()){
         fprintf(stderr, "Error initializing protocol proto_hems");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BFTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bftp_struct()){
         fprintf(stderr, "Error initializing protocol proto_bftp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SGMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sgmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_sgmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETSC_PROD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netsc_prod_struct()){
         fprintf(stderr, "Error initializing protocol proto_netsc_prod");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETSC_DEV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netsc_dev_struct()){
         fprintf(stderr, "Error initializing protocol proto_netsc_dev");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SQLSRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sqlsrv_struct()){
         fprintf(stderr, "Error initializing protocol proto_sqlsrv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KNET_CMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_knet_cmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_knet_cmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PCMAIL_SRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pcmail_srv_struct()){
         fprintf(stderr, "Error initializing protocol proto_pcmail_srv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NSS_ROUTING //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nss_routing_struct()){
         fprintf(stderr, "Error initializing protocol proto_nss_routing");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SGMP_TRAPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sgmp_traps_struct()){
         fprintf(stderr, "Error initializing protocol proto_sgmp_traps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNMPTRAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_snmptrap_struct()){
         fprintf(stderr, "Error initializing protocol proto_snmptrap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CMIP_MAN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cmip_man_struct()){
         fprintf(stderr, "Error initializing protocol proto_cmip_man");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CMIP_AGENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cmip_agent_struct()){
         fprintf(stderr, "Error initializing protocol proto_cmip_agent");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XNS_COURIER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xns_courier_struct()){
         fprintf(stderr, "Error initializing protocol proto_xns_courier");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_S_NET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_s_net_struct()){
         fprintf(stderr, "Error initializing protocol proto_s_net");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NAMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_namp_struct()){
         fprintf(stderr, "Error initializing protocol proto_namp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RSVD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rsvd_struct()){
         fprintf(stderr, "Error initializing protocol proto_rsvd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SEND //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_send_struct()){
         fprintf(stderr, "Error initializing protocol proto_send");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PRINT_SRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_print_srv_struct()){
         fprintf(stderr, "Error initializing protocol proto_print_srv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MULTIPLEX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_multiplex_struct()){
         fprintf(stderr, "Error initializing protocol proto_multiplex");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CL_1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cl_1_struct()){
         fprintf(stderr, "Error initializing protocol proto_cl_1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CL1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cl1_struct()){
         fprintf(stderr, "Error initializing protocol proto_cl1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XYPLEX_MUX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xyplex_mux_struct()){
         fprintf(stderr, "Error initializing protocol proto_xyplex_mux");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAILQ //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mailq_struct()){
         fprintf(stderr, "Error initializing protocol proto_mailq");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VMNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vmnet_struct()){
         fprintf(stderr, "Error initializing protocol proto_vmnet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GENRAD_MUX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_genrad_mux_struct()){
         fprintf(stderr, "Error initializing protocol proto_genrad_mux");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NEXTSTEP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nextstep_struct()){
         fprintf(stderr, "Error initializing protocol proto_nextstep");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RIS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ris_struct()){
         fprintf(stderr, "Error initializing protocol proto_ris");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UNIFY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_unify_struct()){
         fprintf(stderr, "Error initializing protocol proto_unify");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AUDIT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_audit_struct()){
         fprintf(stderr, "Error initializing protocol proto_audit");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OCBINDER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ocbinder_struct()){
         fprintf(stderr, "Error initializing protocol proto_ocbinder");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OCSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ocserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_ocserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_REMOTE_KIS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_remote_kis_struct()){
         fprintf(stderr, "Error initializing protocol proto_remote_kis");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KIS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_kis_struct()){
         fprintf(stderr, "Error initializing protocol proto_kis");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_aci_struct()){
         fprintf(stderr, "Error initializing protocol proto_aci");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MUMPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mumps_struct()){
         fprintf(stderr, "Error initializing protocol proto_mumps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QFT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_qft_struct()){
         fprintf(stderr, "Error initializing protocol proto_qft");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GACP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gacp_struct()){
         fprintf(stderr, "Error initializing protocol proto_gacp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PROSPERO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_prospero_struct()){
         fprintf(stderr, "Error initializing protocol proto_prospero");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OSU_NMS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_osu_nms_struct()){
         fprintf(stderr, "Error initializing protocol proto_osu_nms");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SRMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_srmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_srmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DN6_NLM_AUD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dn6_nlm_aud_struct()){
         fprintf(stderr, "Error initializing protocol proto_dn6_nlm_aud");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DN6_SMM_RED //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dn6_smm_red_struct()){
         fprintf(stderr, "Error initializing protocol proto_dn6_smm_red");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DLS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dls_struct()){
         fprintf(stderr, "Error initializing protocol proto_dls");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DLS_MON //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dls_mon_struct()){
         fprintf(stderr, "Error initializing protocol proto_dls_mon");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMUX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smux_struct()){
         fprintf(stderr, "Error initializing protocol proto_smux");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SRC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_src_struct()){
         fprintf(stderr, "Error initializing protocol proto_src");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_RTMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_rtmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_rtmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_NBP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_nbp_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_nbp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_3_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_ECHO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_echo_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_echo");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_5 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_5_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_5");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_ZIS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_zis_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_zis");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_7 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_7_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_7");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AT_8 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_at_8_struct()){
         fprintf(stderr, "Error initializing protocol proto_at_8");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QMTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_qmtp_struct()){
         fprintf(stderr, "Error initializing protocol proto_qmtp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_Z39_50 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_z39_50_struct()){
         fprintf(stderr, "Error initializing protocol proto_z39_50");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_914C_G //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_914c_g_struct()){
         fprintf(stderr, "Error initializing protocol proto_914c_g");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_914CG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_914cg_struct()){
         fprintf(stderr, "Error initializing protocol proto_914cg");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ANET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_anet_struct()){
         fprintf(stderr, "Error initializing protocol proto_anet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ipx_struct()){
         fprintf(stderr, "Error initializing protocol proto_ipx");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VMPWSCS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vmpwscs_struct()){
         fprintf(stderr, "Error initializing protocol proto_vmpwscs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOFTPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_softpc_struct()){
         fprintf(stderr, "Error initializing protocol proto_softpc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CAILIC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cailic_struct()){
         fprintf(stderr, "Error initializing protocol proto_cailic");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DBASE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dbase_struct()){
         fprintf(stderr, "Error initializing protocol proto_dbase");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mpp_struct()){
         fprintf(stderr, "Error initializing protocol proto_mpp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UARPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uarps_struct()){
         fprintf(stderr, "Error initializing protocol proto_uarps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMAP3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_imap3_struct()){
         fprintf(stderr, "Error initializing protocol proto_imap3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FLN_SPX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_fln_spx_struct()){
         fprintf(stderr, "Error initializing protocol proto_fln_spx");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RSH_SPX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rsh_spx_struct()){
         fprintf(stderr, "Error initializing protocol proto_rsh_spx");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CDC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cdc_struct()){
         fprintf(stderr, "Error initializing protocol proto_cdc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MASQDIALER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_masqdialer_struct()){
         fprintf(stderr, "Error initializing protocol proto_masqdialer");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DIRECT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_direct_struct()){
         fprintf(stderr, "Error initializing protocol proto_direct");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUR_MEAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sur_meas_struct()){
         fprintf(stderr, "Error initializing protocol proto_sur_meas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_INBUSINESS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_inbusiness_struct()){
         fprintf(stderr, "Error initializing protocol proto_inbusiness");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LINK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_link_struct()){
         fprintf(stderr, "Error initializing protocol proto_link");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DSP3270 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dsp3270_struct()){
         fprintf(stderr, "Error initializing protocol proto_dsp3270");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUBNTBCST_TFTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_subntbcst_tftp_struct()){
         fprintf(stderr, "Error initializing protocol proto_subntbcst_tftp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BHFHS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bhfhs_struct()){
         fprintf(stderr, "Error initializing protocol proto_bhfhs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_set_struct()){
         fprintf(stderr, "Error initializing protocol proto_set");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ESRO_GEN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_esro_gen_struct()){
         fprintf(stderr, "Error initializing protocol proto_esro_gen");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPENPORT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_openport_struct()){
         fprintf(stderr, "Error initializing protocol proto_openport");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NSIIOPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nsiiops_struct()){
         fprintf(stderr, "Error initializing protocol proto_nsiiops");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARCISDMS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_arcisdms_struct()){
         fprintf(stderr, "Error initializing protocol proto_arcisdms");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HDAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hdap_struct()){
         fprintf(stderr, "Error initializing protocol proto_hdap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BGMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bgmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_bgmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_X_BONE_CTL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_x_bone_ctl_struct()){
         fprintf(stderr, "Error initializing protocol proto_x_bone_ctl");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SST //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sst_struct()){
         fprintf(stderr, "Error initializing protocol proto_sst");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TD_SERVICE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_td_service_struct()){
         fprintf(stderr, "Error initializing protocol proto_td_service");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TD_REPLICA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_td_replica_struct()){
         fprintf(stderr, "Error initializing protocol proto_td_replica");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GIST //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gist_struct()){
         fprintf(stderr, "Error initializing protocol proto_gist");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PT_TLS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pt_tls_struct()){
         fprintf(stderr, "Error initializing protocol proto_pt_tls");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_MGMT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_http_mgmt_struct()){
         fprintf(stderr, "Error initializing protocol proto_http_mgmt");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PERSONAL_LINK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_personal_link_struct()){
         fprintf(stderr, "Error initializing protocol proto_personal_link");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CABLEPORT_AX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cableport_ax_struct()){
         fprintf(stderr, "Error initializing protocol proto_cableport_ax");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RESCAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rescap_struct()){
         fprintf(stderr, "Error initializing protocol proto_rescap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CORERJD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_corerjd_struct()){
         fprintf(stderr, "Error initializing protocol proto_corerjd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FXP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_fxp_struct()){
         fprintf(stderr, "Error initializing protocol proto_fxp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_K_BLOCK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_k_block_struct()){
         fprintf(stderr, "Error initializing protocol proto_k_block");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NOVASTORBAKCUP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_novastorbakcup_struct()){
         fprintf(stderr, "Error initializing protocol proto_novastorbakcup");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTRUSTTIME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entrusttime_struct()){
         fprintf(stderr, "Error initializing protocol proto_entrusttime");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BHMDS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bhmds_struct()){
         fprintf(stderr, "Error initializing protocol proto_bhmds");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASIP_WEBADMIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_asip_webadmin_struct()){
         fprintf(stderr, "Error initializing protocol proto_asip_webadmin");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VSLMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vslmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_vslmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAGENTA_LOGIC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_magenta_logic_struct()){
         fprintf(stderr, "Error initializing protocol proto_magenta_logic");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPALIS_ROBOT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_opalis_robot_struct()){
         fprintf(stderr, "Error initializing protocol proto_opalis_robot");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DPSI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dpsi_struct()){
         fprintf(stderr, "Error initializing protocol proto_dpsi");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DECAUTH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_decauth_struct()){
         fprintf(stderr, "Error initializing protocol proto_decauth");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZANNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_zannet_struct()){
         fprintf(stderr, "Error initializing protocol proto_zannet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PKIX_TIMESTAMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pkix_timestamp_struct()){
         fprintf(stderr, "Error initializing protocol proto_pkix_timestamp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PTP_EVENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ptp_event_struct()){
         fprintf(stderr, "Error initializing protocol proto_ptp_event");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PTP_GENERAL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ptp_general_struct()){
         fprintf(stderr, "Error initializing protocol proto_ptp_general");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PIP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pip_struct()){
         fprintf(stderr, "Error initializing protocol proto_pip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RTSPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rtsps_struct()){
         fprintf(stderr, "Error initializing protocol proto_rtsps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RPKI_RTR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rpki_rtr_struct()){
         fprintf(stderr, "Error initializing protocol proto_rpki_rtr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RPKI_RTR_TLS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rpki_rtr_tls_struct()){
         fprintf(stderr, "Error initializing protocol proto_rpki_rtr_tls");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TEXAR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_texar_struct()){
         fprintf(stderr, "Error initializing protocol proto_texar");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PDAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pdap_struct()){
         fprintf(stderr, "Error initializing protocol proto_pdap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PAWSERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pawserv_struct()){
         fprintf(stderr, "Error initializing protocol proto_pawserv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ZSERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_zserv_struct()){
         fprintf(stderr, "Error initializing protocol proto_zserv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FATSERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_fatserv_struct()){
         fprintf(stderr, "Error initializing protocol proto_fatserv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CSI_SGWP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_csi_sgwp_struct()){
         fprintf(stderr, "Error initializing protocol proto_csi_sgwp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MFTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mftp_struct()){
         fprintf(stderr, "Error initializing protocol proto_mftp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MATIP_TYPE_A //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_matip_type_a_struct()){
         fprintf(stderr, "Error initializing protocol proto_matip_type_a");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MATIP_TYPE_B //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_matip_type_b_struct()){
         fprintf(stderr, "Error initializing protocol proto_matip_type_b");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BHOETTY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bhoetty_struct()){
         fprintf(stderr, "Error initializing protocol proto_bhoetty");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DTAG_STE_SB //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dtag_ste_sb_struct()){
         fprintf(stderr, "Error initializing protocol proto_dtag_ste_sb");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BHOEDAP4 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bhoedap4_struct()){
         fprintf(stderr, "Error initializing protocol proto_bhoedap4");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NDSAUTH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ndsauth_struct()){
         fprintf(stderr, "Error initializing protocol proto_ndsauth");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BH611 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bh611_struct()){
         fprintf(stderr, "Error initializing protocol proto_bh611");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DATEX_ASN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_datex_asn_struct()){
         fprintf(stderr, "Error initializing protocol proto_datex_asn");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CLOANTO_NET_1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cloanto_net_1_struct()){
         fprintf(stderr, "Error initializing protocol proto_cloanto_net_1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BHEVENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bhevent_struct()){
         fprintf(stderr, "Error initializing protocol proto_bhevent");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SHRINKWRAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_shrinkwrap_struct()){
         fprintf(stderr, "Error initializing protocol proto_shrinkwrap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NSRMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nsrmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_nsrmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCOI2ODIALOG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_scoi2odialog_struct()){
         fprintf(stderr, "Error initializing protocol proto_scoi2odialog");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SEMANTIX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_semantix_struct()){
         fprintf(stderr, "Error initializing protocol proto_semantix");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SRSSEND //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_srssend_struct()){
         fprintf(stderr, "Error initializing protocol proto_srssend");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RSVP_TUNNEL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rsvp_tunnel_struct()){
         fprintf(stderr, "Error initializing protocol proto_rsvp_tunnel");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AURORA_CMGR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_aurora_cmgr_struct()){
         fprintf(stderr, "Error initializing protocol proto_aurora_cmgr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DTK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dtk_struct()){
         fprintf(stderr, "Error initializing protocol proto_dtk");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ODMR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_odmr_struct()){
         fprintf(stderr, "Error initializing protocol proto_odmr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MORTGAGEWARE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mortgageware_struct()){
         fprintf(stderr, "Error initializing protocol proto_mortgageware");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QBIKGDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_qbikgdp_struct()){
         fprintf(stderr, "Error initializing protocol proto_qbikgdp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RPC2PORTMAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rpc2portmap_struct()){
         fprintf(stderr, "Error initializing protocol proto_rpc2portmap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CODAAUTH2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_codaauth2_struct()){
         fprintf(stderr, "Error initializing protocol proto_codaauth2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CLEARCASE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_clearcase_struct()){
         fprintf(stderr, "Error initializing protocol proto_clearcase");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ULISTPROC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ulistproc_struct()){
         fprintf(stderr, "Error initializing protocol proto_ulistproc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEGENT_1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_legent_1_struct()){
         fprintf(stderr, "Error initializing protocol proto_legent_1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LEGENT_2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_legent_2_struct()){
         fprintf(stderr, "Error initializing protocol proto_legent_2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HASSLE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hassle_struct()){
         fprintf(stderr, "Error initializing protocol proto_hassle");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NIP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nip_struct()){
         fprintf(stderr, "Error initializing protocol proto_nip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TNETOS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tnetos_struct()){
         fprintf(stderr, "Error initializing protocol proto_tnetos");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DSETOS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dsetos_struct()){
         fprintf(stderr, "Error initializing protocol proto_dsetos");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IS99C //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_is99c_struct()){
         fprintf(stderr, "Error initializing protocol proto_is99c");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IS99S //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_is99s_struct()){
         fprintf(stderr, "Error initializing protocol proto_is99s");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HP_COLLECTOR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hp_collector_struct()){
         fprintf(stderr, "Error initializing protocol proto_hp_collector");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HP_MANAGED_NODE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hp_managed_node_struct()){
         fprintf(stderr, "Error initializing protocol proto_hp_managed_node");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HP_ALARM_MGR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hp_alarm_mgr_struct()){
         fprintf(stderr, "Error initializing protocol proto_hp_alarm_mgr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARNS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_arns_struct()){
         fprintf(stderr, "Error initializing protocol proto_arns");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IBM_APP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ibm_app_struct()){
         fprintf(stderr, "Error initializing protocol proto_ibm_app");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_asa_struct()){
         fprintf(stderr, "Error initializing protocol proto_asa");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AURP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_aurp_struct()){
         fprintf(stderr, "Error initializing protocol proto_aurp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UNIDATA_LDM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_unidata_ldm_struct()){
         fprintf(stderr, "Error initializing protocol proto_unidata_ldm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UIS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uis_struct()){
         fprintf(stderr, "Error initializing protocol proto_uis");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SYNOTICS_RELAY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_synotics_relay_struct()){
         fprintf(stderr, "Error initializing protocol proto_synotics_relay");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SYNOTICS_BROKER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_synotics_broker_struct()){
         fprintf(stderr, "Error initializing protocol proto_synotics_broker");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_META5 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_meta5_struct()){
         fprintf(stderr, "Error initializing protocol proto_meta5");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EMBL_NDT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_embl_ndt_struct()){
         fprintf(stderr, "Error initializing protocol proto_embl_ndt");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_netcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETWARE_IP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netware_ip_struct()){
         fprintf(stderr, "Error initializing protocol proto_netware_ip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MPTN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mptn_struct()){
         fprintf(stderr, "Error initializing protocol proto_mptn");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISO_TSAP_C2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iso_tsap_c2_struct()){
         fprintf(stderr, "Error initializing protocol proto_iso_tsap_c2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OSB_SD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_osb_sd_struct()){
         fprintf(stderr, "Error initializing protocol proto_osb_sd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ups_struct()){
         fprintf(stderr, "Error initializing protocol proto_ups");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GENIE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_genie_struct()){
         fprintf(stderr, "Error initializing protocol proto_genie");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DECAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_decap_struct()){
         fprintf(stderr, "Error initializing protocol proto_decap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NCED //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nced_struct()){
         fprintf(stderr, "Error initializing protocol proto_nced");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NCLD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ncld_struct()){
         fprintf(stderr, "Error initializing protocol proto_ncld");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IMSP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_imsp_struct()){
         fprintf(stderr, "Error initializing protocol proto_imsp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TIMBUKTU //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_timbuktu_struct()){
         fprintf(stderr, "Error initializing protocol proto_timbuktu");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PRM_SM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_prm_sm_struct()){
         fprintf(stderr, "Error initializing protocol proto_prm_sm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PRM_NM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_prm_nm_struct()){
         fprintf(stderr, "Error initializing protocol proto_prm_nm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DECLADEBUG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_decladebug_struct()){
         fprintf(stderr, "Error initializing protocol proto_decladebug");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RMT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rmt_struct()){
         fprintf(stderr, "Error initializing protocol proto_rmt");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SYNOPTICS_TRAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_synoptics_trap_struct()){
         fprintf(stderr, "Error initializing protocol proto_synoptics_trap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMSP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smsp_struct()){
         fprintf(stderr, "Error initializing protocol proto_smsp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_INFOSEEK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_infoseek_struct()){
         fprintf(stderr, "Error initializing protocol proto_infoseek");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bnet_struct()){
         fprintf(stderr, "Error initializing protocol proto_bnet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SILVERPLATTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_silverplatter_struct()){
         fprintf(stderr, "Error initializing protocol proto_silverplatter");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ONMUX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_onmux_struct()){
         fprintf(stderr, "Error initializing protocol proto_onmux");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HYPER_G //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hyper_g_struct()){
         fprintf(stderr, "Error initializing protocol proto_hyper_g");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARIEL1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ariel1_struct()){
         fprintf(stderr, "Error initializing protocol proto_ariel1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMPTE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smpte_struct()){
         fprintf(stderr, "Error initializing protocol proto_smpte");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARIEL2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ariel2_struct()){
         fprintf(stderr, "Error initializing protocol proto_ariel2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ARIEL3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ariel3_struct()){
         fprintf(stderr, "Error initializing protocol proto_ariel3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPC_JOB_START //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_opc_job_start_struct()){
         fprintf(stderr, "Error initializing protocol proto_opc_job_start");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPC_JOB_TRACK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_opc_job_track_struct()){
         fprintf(stderr, "Error initializing protocol proto_opc_job_track");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ICAD_EL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_icad_el_struct()){
         fprintf(stderr, "Error initializing protocol proto_icad_el");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMARTSDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smartsdp_struct()){
         fprintf(stderr, "Error initializing protocol proto_smartsdp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SVRLOC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_svrloc_struct()){
         fprintf(stderr, "Error initializing protocol proto_svrloc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OCS_CMU //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ocs_cmu_struct()){
         fprintf(stderr, "Error initializing protocol proto_ocs_cmu");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OCS_AMU //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ocs_amu_struct()){
         fprintf(stderr, "Error initializing protocol proto_ocs_amu");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UTMPSD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_utmpsd_struct()){
         fprintf(stderr, "Error initializing protocol proto_utmpsd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UTMPCD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_utmpcd_struct()){
         fprintf(stderr, "Error initializing protocol proto_utmpcd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IASD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iasd_struct()){
         fprintf(stderr, "Error initializing protocol proto_iasd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NNSP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nnsp_struct()){
         fprintf(stderr, "Error initializing protocol proto_nnsp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MOBILEIP_AGENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mobileip_agent_struct()){
         fprintf(stderr, "Error initializing protocol proto_mobileip_agent");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MOBILIP_MN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mobilip_mn_struct()){
         fprintf(stderr, "Error initializing protocol proto_mobilip_mn");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DNA_CML //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dna_cml_struct()){
         fprintf(stderr, "Error initializing protocol proto_dna_cml");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMSCM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_comscm_struct()){
         fprintf(stderr, "Error initializing protocol proto_comscm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DSFGW //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dsfgw_struct()){
         fprintf(stderr, "Error initializing protocol proto_dsfgw");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DASP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dasp_struct()){
         fprintf(stderr, "Error initializing protocol proto_dasp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SGCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sgcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_sgcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DECVMS_SYSMGT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_decvms_sysmgt_struct()){
         fprintf(stderr, "Error initializing protocol proto_decvms_sysmgt");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CVC_HOSTD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cvc_hostd_struct()){
         fprintf(stderr, "Error initializing protocol proto_cvc_hostd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_https_struct()){
         fprintf(stderr, "Error initializing protocol proto_https");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_snpp_struct()){
         fprintf(stderr, "Error initializing protocol proto_snpp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MICROSOFT_DS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_microsoft_ds_struct()){
         fprintf(stderr, "Error initializing protocol proto_microsoft_ds");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DDM_RDB //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ddm_rdb_struct()){
         fprintf(stderr, "Error initializing protocol proto_ddm_rdb");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DDM_DFM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ddm_dfm_struct()){
         fprintf(stderr, "Error initializing protocol proto_ddm_dfm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DDM_SSL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ddm_ssl_struct()){
         fprintf(stderr, "Error initializing protocol proto_ddm_ssl");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AS_SERVERMAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_as_servermap_struct()){
         fprintf(stderr, "Error initializing protocol proto_as_servermap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_tserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SFS_SMP_NET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sfs_smp_net_struct()){
         fprintf(stderr, "Error initializing protocol proto_sfs_smp_net");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SFS_CONFIG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sfs_config_struct()){
         fprintf(stderr, "Error initializing protocol proto_sfs_config");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CREATIVESERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_creativeserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_creativeserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CONTENTSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_contentserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_contentserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CREATIVEPARTNR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_creativepartnr_struct()){
         fprintf(stderr, "Error initializing protocol proto_creativepartnr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MACON_TCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_macon_tcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_macon_tcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MACON_UDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_macon_udp_struct()){
         fprintf(stderr, "Error initializing protocol proto_macon_udp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCOHELP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_scohelp_struct()){
         fprintf(stderr, "Error initializing protocol proto_scohelp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLEQTC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_appleqtc_struct()){
         fprintf(stderr, "Error initializing protocol proto_appleqtc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AMPR_RCMD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ampr_rcmd_struct()){
         fprintf(stderr, "Error initializing protocol proto_ampr_rcmd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SKRONK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_skronk_struct()){
         fprintf(stderr, "Error initializing protocol proto_skronk");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DATASURFSRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_datasurfsrv_struct()){
         fprintf(stderr, "Error initializing protocol proto_datasurfsrv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DATASURFSRVSEC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_datasurfsrvsec_struct()){
         fprintf(stderr, "Error initializing protocol proto_datasurfsrvsec");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ALPES //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_alpes_struct()){
         fprintf(stderr, "Error initializing protocol proto_alpes");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KPASSWD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_kpasswd_struct()){
         fprintf(stderr, "Error initializing protocol proto_kpasswd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_URD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_urd_struct()){
         fprintf(stderr, "Error initializing protocol proto_urd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IGMPV3LITE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_igmpv3lite_struct()){
         fprintf(stderr, "Error initializing protocol proto_igmpv3lite");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DIGITAL_VRC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_digital_vrc_struct()){
         fprintf(stderr, "Error initializing protocol proto_digital_vrc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MYLEX_MAPD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mylex_mapd_struct()){
         fprintf(stderr, "Error initializing protocol proto_mylex_mapd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PHOTURIS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_photuris_struct()){
         fprintf(stderr, "Error initializing protocol proto_photuris");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_rcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCX_PROXY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_scx_proxy_struct()){
         fprintf(stderr, "Error initializing protocol proto_scx_proxy");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MONDEX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mondex_struct()){
         fprintf(stderr, "Error initializing protocol proto_mondex");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LJK_LOGIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ljk_login_struct()){
         fprintf(stderr, "Error initializing protocol proto_ljk_login");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HYBRID_POP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hybrid_pop_struct()){
         fprintf(stderr, "Error initializing protocol proto_hybrid_pop");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TN_TL_W1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tn_tl_w1_struct()){
         fprintf(stderr, "Error initializing protocol proto_tn_tl_w1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TN_TL_W2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tn_tl_w2_struct()){
         fprintf(stderr, "Error initializing protocol proto_tn_tl_w2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TCPNETHASPSRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tcpnethaspsrv_struct()){
         fprintf(stderr, "Error initializing protocol proto_tcpnethaspsrv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TN_TL_FD1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tn_tl_fd1_struct()){
         fprintf(stderr, "Error initializing protocol proto_tn_tl_fd1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SS7NS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ss7ns_struct()){
         fprintf(stderr, "Error initializing protocol proto_ss7ns");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SPSC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_spsc_struct()){
         fprintf(stderr, "Error initializing protocol proto_spsc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IAFSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iafserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_iafserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IAFDBASE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iafdbase_struct()){
         fprintf(stderr, "Error initializing protocol proto_iafdbase");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ph_struct()){
         fprintf(stderr, "Error initializing protocol proto_ph");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BGS_NSI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bgs_nsi_struct()){
         fprintf(stderr, "Error initializing protocol proto_bgs_nsi");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ULPNET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ulpnet_struct()){
         fprintf(stderr, "Error initializing protocol proto_ulpnet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_INTEGRA_SME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_integra_sme_struct()){
         fprintf(stderr, "Error initializing protocol proto_integra_sme");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_POWERBURST //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_powerburst_struct()){
         fprintf(stderr, "Error initializing protocol proto_powerburst");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AVIAN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_avian_struct()){
         fprintf(stderr, "Error initializing protocol proto_avian");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SAFT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_saft_struct()){
         fprintf(stderr, "Error initializing protocol proto_saft");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GSS_HTTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gss_http_struct()){
         fprintf(stderr, "Error initializing protocol proto_gss_http");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NEST_PROTOCOL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nest_protocol_struct()){
         fprintf(stderr, "Error initializing protocol proto_nest_protocol");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MICOM_PFS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_micom_pfs_struct()){
         fprintf(stderr, "Error initializing protocol proto_micom_pfs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GO_LOGIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_go_login_struct()){
         fprintf(stderr, "Error initializing protocol proto_go_login");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TICF_1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ticf_1_struct()){
         fprintf(stderr, "Error initializing protocol proto_ticf_1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TICF_2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ticf_2_struct()){
         fprintf(stderr, "Error initializing protocol proto_ticf_2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_POV_RAY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pov_ray_struct()){
         fprintf(stderr, "Error initializing protocol proto_pov_ray");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_INTECOURIER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_intecourier_struct()){
         fprintf(stderr, "Error initializing protocol proto_intecourier");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PIM_RP_DISC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pim_rp_disc_struct()){
         fprintf(stderr, "Error initializing protocol proto_pim_rp_disc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RETROSPECT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_retrospect_struct()){
         fprintf(stderr, "Error initializing protocol proto_retrospect");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SIAM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_siam_struct()){
         fprintf(stderr, "Error initializing protocol proto_siam");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISO_ILL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iso_ill_struct()){
         fprintf(stderr, "Error initializing protocol proto_iso_ill");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISAKMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_isakmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_isakmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_STMF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_stmf_struct()){
         fprintf(stderr, "Error initializing protocol proto_stmf");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MBAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mbap_struct()){
         fprintf(stderr, "Error initializing protocol proto_mbap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_INTRINSA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_intrinsa_struct()){
         fprintf(stderr, "Error initializing protocol proto_intrinsa");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CITADEL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_citadel_struct()){
         fprintf(stderr, "Error initializing protocol proto_citadel");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAILBOX_LM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mailbox_lm_struct()){
         fprintf(stderr, "Error initializing protocol proto_mailbox_lm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OHIMSRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ohimsrv_struct()){
         fprintf(stderr, "Error initializing protocol proto_ohimsrv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CRS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_crs_struct()){
         fprintf(stderr, "Error initializing protocol proto_crs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XVTTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xvttp_struct()){
         fprintf(stderr, "Error initializing protocol proto_xvttp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNARE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_snare_struct()){
         fprintf(stderr, "Error initializing protocol proto_snare");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_fcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_fcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PASSGO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_passgo_struct()){
         fprintf(stderr, "Error initializing protocol proto_passgo");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EXEC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_exec_struct()){
         fprintf(stderr, "Error initializing protocol proto_exec");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMSAT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_comsat_struct()){
         fprintf(stderr, "Error initializing protocol proto_comsat");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BIFF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_biff_struct()){
         fprintf(stderr, "Error initializing protocol proto_biff");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LOGIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_login_struct()){
         fprintf(stderr, "Error initializing protocol proto_login");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WHO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_who_struct()){
         fprintf(stderr, "Error initializing protocol proto_who");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SHELL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_shell_struct()){
         fprintf(stderr, "Error initializing protocol proto_shell");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PRINTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_printer_struct()){
         fprintf(stderr, "Error initializing protocol proto_printer");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VIDEOTEX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_videotex_struct()){
         fprintf(stderr, "Error initializing protocol proto_videotex");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TALK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_talk_struct()){
         fprintf(stderr, "Error initializing protocol proto_talk");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NTALK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ntalk_struct()){
         fprintf(stderr, "Error initializing protocol proto_ntalk");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UTIME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_utime_struct()){
         fprintf(stderr, "Error initializing protocol proto_utime");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EFS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_efs_struct()){
         fprintf(stderr, "Error initializing protocol proto_efs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ROUTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_router_struct()){
         fprintf(stderr, "Error initializing protocol proto_router");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RIPNG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ripng_struct()){
         fprintf(stderr, "Error initializing protocol proto_ripng");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ULP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ulp_struct()){
         fprintf(stderr, "Error initializing protocol proto_ulp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IBM_DB2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ibm_db2_struct()){
         fprintf(stderr, "Error initializing protocol proto_ibm_db2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ncp_struct()){
         fprintf(stderr, "Error initializing protocol proto_ncp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TIMED //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_timed_struct()){
         fprintf(stderr, "Error initializing protocol proto_timed");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TEMPO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tempo_struct()){
         fprintf(stderr, "Error initializing protocol proto_tempo");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_STX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_stx_struct()){
         fprintf(stderr, "Error initializing protocol proto_stx");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CUSTIX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_custix_struct()){
         fprintf(stderr, "Error initializing protocol proto_custix");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRC_SERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_irc_serv_struct()){
         fprintf(stderr, "Error initializing protocol proto_irc_serv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COURIER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_courier_struct()){
         fprintf(stderr, "Error initializing protocol proto_courier");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CONFERENCE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_conference_struct()){
         fprintf(stderr, "Error initializing protocol proto_conference");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETNEWS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netnews_struct()){
         fprintf(stderr, "Error initializing protocol proto_netnews");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETWALL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netwall_struct()){
         fprintf(stderr, "Error initializing protocol proto_netwall");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WINDREAM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_windream_struct()){
         fprintf(stderr, "Error initializing protocol proto_windream");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IIOP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iiop_struct()){
         fprintf(stderr, "Error initializing protocol proto_iiop");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPALIS_RDV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_opalis_rdv_struct()){
         fprintf(stderr, "Error initializing protocol proto_opalis_rdv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NMSP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nmsp_struct()){
         fprintf(stderr, "Error initializing protocol proto_nmsp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GDOMAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gdomap_struct()){
         fprintf(stderr, "Error initializing protocol proto_gdomap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_APERTUS_LDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_apertus_ldp_struct()){
         fprintf(stderr, "Error initializing protocol proto_apertus_ldp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UUCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uucp_struct()){
         fprintf(stderr, "Error initializing protocol proto_uucp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UUCP_RLOGIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uucp_rlogin_struct()){
         fprintf(stderr, "Error initializing protocol proto_uucp_rlogin");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMMERCE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_commerce_struct()){
         fprintf(stderr, "Error initializing protocol proto_commerce");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KLOGIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_klogin_struct()){
         fprintf(stderr, "Error initializing protocol proto_klogin");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KSHELL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_kshell_struct()){
         fprintf(stderr, "Error initializing protocol proto_kshell");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLEQTCSRVR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_appleqtcsrvr_struct()){
         fprintf(stderr, "Error initializing protocol proto_appleqtcsrvr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DHCPV6_CLIENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dhcpv6_client_struct()){
         fprintf(stderr, "Error initializing protocol proto_dhcpv6_client");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DHCPV6_SERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dhcpv6_server_struct()){
         fprintf(stderr, "Error initializing protocol proto_dhcpv6_server");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AFPOVERTCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_afpovertcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_afpovertcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDFP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_idfp_struct()){
         fprintf(stderr, "Error initializing protocol proto_idfp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NEW_RWHO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_new_rwho_struct()){
         fprintf(stderr, "Error initializing protocol proto_new_rwho");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CYBERCASH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cybercash_struct()){
         fprintf(stderr, "Error initializing protocol proto_cybercash");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEVSHR_NTS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_devshr_nts_struct()){
         fprintf(stderr, "Error initializing protocol proto_devshr_nts");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PIRP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pirp_struct()){
         fprintf(stderr, "Error initializing protocol proto_pirp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DSF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dsf_struct()){
         fprintf(stderr, "Error initializing protocol proto_dsf");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_REMOTEFS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_remotefs_struct()){
         fprintf(stderr, "Error initializing protocol proto_remotefs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OPENVMS_SYSIPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_openvms_sysipc_struct()){
         fprintf(stderr, "Error initializing protocol proto_openvms_sysipc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SDNSKMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sdnskmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_sdnskmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TEEDTAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_teedtap_struct()){
         fprintf(stderr, "Error initializing protocol proto_teedtap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RMONITOR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rmonitor_struct()){
         fprintf(stderr, "Error initializing protocol proto_rmonitor");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MONITOR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_monitor_struct()){
         fprintf(stderr, "Error initializing protocol proto_monitor");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CHSHELL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_chshell_struct()){
         fprintf(stderr, "Error initializing protocol proto_chshell");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NNTPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nntps_struct()){
         fprintf(stderr, "Error initializing protocol proto_nntps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_9PFS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_9pfs_struct()){
         fprintf(stderr, "Error initializing protocol proto_9pfs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WHOAMI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_whoami_struct()){
         fprintf(stderr, "Error initializing protocol proto_whoami");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_STREETTALK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_streettalk_struct()){
         fprintf(stderr, "Error initializing protocol proto_streettalk");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BANYAN_RPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_banyan_rpc_struct()){
         fprintf(stderr, "Error initializing protocol proto_banyan_rpc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MS_SHUTTLE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ms_shuttle_struct()){
         fprintf(stderr, "Error initializing protocol proto_ms_shuttle");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MS_ROME //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ms_rome_struct()){
         fprintf(stderr, "Error initializing protocol proto_ms_rome");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_METER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_meter_struct()){
         fprintf(stderr, "Error initializing protocol proto_meter");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SONAR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sonar_struct()){
         fprintf(stderr, "Error initializing protocol proto_sonar");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BANYAN_VIP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_banyan_vip_struct()){
         fprintf(stderr, "Error initializing protocol proto_banyan_vip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FTP_AGENT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ftp_agent_struct()){
         fprintf(stderr, "Error initializing protocol proto_ftp_agent");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VEMMI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vemmi_struct()){
         fprintf(stderr, "Error initializing protocol proto_vemmi");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPCD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ipcd_struct()){
         fprintf(stderr, "Error initializing protocol proto_ipcd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VNAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vnas_struct()){
         fprintf(stderr, "Error initializing protocol proto_vnas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPDD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ipdd_struct()){
         fprintf(stderr, "Error initializing protocol proto_ipdd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DECBSRV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_decbsrv_struct()){
         fprintf(stderr, "Error initializing protocol proto_decbsrv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SNTP_HEARTBEAT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sntp_heartbeat_struct()){
         fprintf(stderr, "Error initializing protocol proto_sntp_heartbeat");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bdp_struct()){
         fprintf(stderr, "Error initializing protocol proto_bdp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCC_SECURITY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_scc_security_struct()){
         fprintf(stderr, "Error initializing protocol proto_scc_security");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PHILIPS_VC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_philips_vc_struct()){
         fprintf(stderr, "Error initializing protocol proto_philips_vc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KEYSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_keyserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_keyserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PASSWORD_CHG //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_password_chg_struct()){
         fprintf(stderr, "Error initializing protocol proto_password_chg");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUBMISSION //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_submission_struct()){
         fprintf(stderr, "Error initializing protocol proto_submission");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CAL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cal_struct()){
         fprintf(stderr, "Error initializing protocol proto_cal");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EYELINK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_eyelink_struct()){
         fprintf(stderr, "Error initializing protocol proto_eyelink");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TNS_CML //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tns_cml_struct()){
         fprintf(stderr, "Error initializing protocol proto_tns_cml");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_ALT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_http_alt_struct()){
         fprintf(stderr, "Error initializing protocol proto_http_alt");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EUDORA_SET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_eudora_set_struct()){
         fprintf(stderr, "Error initializing protocol proto_eudora_set");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HTTP_RPC_EPMAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_http_rpc_epmap_struct()){
         fprintf(stderr, "Error initializing protocol proto_http_rpc_epmap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TPIP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tpip_struct()){
         fprintf(stderr, "Error initializing protocol proto_tpip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CAB_PROTOCOL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cab_protocol_struct()){
         fprintf(stderr, "Error initializing protocol proto_cab_protocol");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMSD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smsd_struct()){
         fprintf(stderr, "Error initializing protocol proto_smsd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PTCNAMESERVICE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ptcnameservice_struct()){
         fprintf(stderr, "Error initializing protocol proto_ptcnameservice");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCO_WEBSRVRMG3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sco_websrvrmg3_struct()){
         fprintf(stderr, "Error initializing protocol proto_sco_websrvrmg3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_acp_struct()){
         fprintf(stderr, "Error initializing protocol proto_acp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IPCSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ipcserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_ipcserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SYSLOG_CONN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_syslog_conn_struct()){
         fprintf(stderr, "Error initializing protocol proto_syslog_conn");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XMLRPC_BEEP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xmlrpc_beep_struct()){
         fprintf(stderr, "Error initializing protocol proto_xmlrpc_beep");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDXP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_idxp_struct()){
         fprintf(stderr, "Error initializing protocol proto_idxp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TUNNEL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tunnel_struct()){
         fprintf(stderr, "Error initializing protocol proto_tunnel");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SOAP_BEEP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_soap_beep_struct()){
         fprintf(stderr, "Error initializing protocol proto_soap_beep");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_URM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_urm_struct()){
         fprintf(stderr, "Error initializing protocol proto_urm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NQS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nqs_struct()){
         fprintf(stderr, "Error initializing protocol proto_nqs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SIFT_UFT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sift_uft_struct()){
         fprintf(stderr, "Error initializing protocol proto_sift_uft");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NPMP_TRAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_npmp_trap_struct()){
         fprintf(stderr, "Error initializing protocol proto_npmp_trap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NPMP_LOCAL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_npmp_local_struct()){
         fprintf(stderr, "Error initializing protocol proto_npmp_local");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NPMP_GUI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_npmp_gui_struct()){
         fprintf(stderr, "Error initializing protocol proto_npmp_gui");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HMMP_IND //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hmmp_ind_struct()){
         fprintf(stderr, "Error initializing protocol proto_hmmp_ind");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HMMP_OP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hmmp_op_struct()){
         fprintf(stderr, "Error initializing protocol proto_hmmp_op");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SSHELL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sshell_struct()){
         fprintf(stderr, "Error initializing protocol proto_sshell");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCO_INETMGR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sco_inetmgr_struct()){
         fprintf(stderr, "Error initializing protocol proto_sco_inetmgr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCO_SYSMGR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sco_sysmgr_struct()){
         fprintf(stderr, "Error initializing protocol proto_sco_sysmgr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCO_DTMGR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sco_dtmgr_struct()){
         fprintf(stderr, "Error initializing protocol proto_sco_dtmgr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEI_ICDA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dei_icda_struct()){
         fprintf(stderr, "Error initializing protocol proto_dei_icda");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COMPAQ_EVM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_compaq_evm_struct()){
         fprintf(stderr, "Error initializing protocol proto_compaq_evm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SCO_WEBSRVRMGR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sco_websrvrmgr_struct()){
         fprintf(stderr, "Error initializing protocol proto_sco_websrvrmgr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ESCP_IP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_escp_ip_struct()){
         fprintf(stderr, "Error initializing protocol proto_escp_ip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_COLLABORATOR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_collaborator_struct()){
         fprintf(stderr, "Error initializing protocol proto_collaborator");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OOB_WS_HTTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_oob_ws_http_struct()){
         fprintf(stderr, "Error initializing protocol proto_oob_ws_http");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASF_RMCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_asf_rmcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_asf_rmcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CRYPTOADMIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cryptoadmin_struct()){
         fprintf(stderr, "Error initializing protocol proto_cryptoadmin");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEC_DLM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dec_dlm_struct()){
         fprintf(stderr, "Error initializing protocol proto_dec_dlm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASIA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_asia_struct()){
         fprintf(stderr, "Error initializing protocol proto_asia");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PASSGO_TIVOLI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_passgo_tivoli_struct()){
         fprintf(stderr, "Error initializing protocol proto_passgo_tivoli");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QMQP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_qmqp_struct()){
         fprintf(stderr, "Error initializing protocol proto_qmqp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_3COM_AMP3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_3com_amp3_struct()){
         fprintf(stderr, "Error initializing protocol proto_3com_amp3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RDA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rda_struct()){
         fprintf(stderr, "Error initializing protocol proto_rda");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BMPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_bmpp_struct()){
         fprintf(stderr, "Error initializing protocol proto_bmpp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SERVSTAT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_servstat_struct()){
         fprintf(stderr, "Error initializing protocol proto_servstat");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GINAD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ginad_struct()){
         fprintf(stderr, "Error initializing protocol proto_ginad");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RLZDBASE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rlzdbase_struct()){
         fprintf(stderr, "Error initializing protocol proto_rlzdbase");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LDAPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ldaps_struct()){
         fprintf(stderr, "Error initializing protocol proto_ldaps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LANSERVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_lanserver_struct()){
         fprintf(stderr, "Error initializing protocol proto_lanserver");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MCNS_SEC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mcns_sec_struct()){
         fprintf(stderr, "Error initializing protocol proto_mcns_sec");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_msdp_struct()){
         fprintf(stderr, "Error initializing protocol proto_msdp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTRUST_SPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entrust_sps_struct()){
         fprintf(stderr, "Error initializing protocol proto_entrust_sps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_REPCMD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_repcmd_struct()){
         fprintf(stderr, "Error initializing protocol proto_repcmd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ESRO_EMSDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_esro_emsdp_struct()){
         fprintf(stderr, "Error initializing protocol proto_esro_emsdp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SANITY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sanity_struct()){
         fprintf(stderr, "Error initializing protocol proto_sanity");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DWR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dwr_struct()){
         fprintf(stderr, "Error initializing protocol proto_dwr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PSSC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pssc_struct()){
         fprintf(stderr, "Error initializing protocol proto_pssc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ldp_struct()){
         fprintf(stderr, "Error initializing protocol proto_ldp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DHCP_FAILOVER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dhcp_failover_struct()){
         fprintf(stderr, "Error initializing protocol proto_dhcp_failover");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RRP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rrp_struct()){
         fprintf(stderr, "Error initializing protocol proto_rrp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CADVIEW_3D //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cadview_3d_struct()){
         fprintf(stderr, "Error initializing protocol proto_cadview_3d");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OBEX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_obex_struct()){
         fprintf(stderr, "Error initializing protocol proto_obex");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IEEE_MMS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ieee_mms_struct()){
         fprintf(stderr, "Error initializing protocol proto_ieee_mms");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HELLO_PORT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hello_port_struct()){
         fprintf(stderr, "Error initializing protocol proto_hello_port");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_REPSCMD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_repscmd_struct()){
         fprintf(stderr, "Error initializing protocol proto_repscmd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AODV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_aodv_struct()){
         fprintf(stderr, "Error initializing protocol proto_aodv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TINC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tinc_struct()){
         fprintf(stderr, "Error initializing protocol proto_tinc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SPMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_spmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_spmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RMC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rmc_struct()){
         fprintf(stderr, "Error initializing protocol proto_rmc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TENFOLD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tenfold_struct()){
         fprintf(stderr, "Error initializing protocol proto_tenfold");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAC_SRVR_ADMIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mac_srvr_admin_struct()){
         fprintf(stderr, "Error initializing protocol proto_mac_srvr_admin");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hap_struct()){
         fprintf(stderr, "Error initializing protocol proto_hap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PFTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pftp_struct()){
         fprintf(stderr, "Error initializing protocol proto_pftp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PURENOISE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_purenoise_struct()){
         fprintf(stderr, "Error initializing protocol proto_purenoise");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OOB_WS_HTTPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_oob_ws_https_struct()){
         fprintf(stderr, "Error initializing protocol proto_oob_ws_https");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASF_SECURE_RMCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_asf_secure_rmcp_struct()){
         fprintf(stderr, "Error initializing protocol proto_asf_secure_rmcp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUN_DR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_sun_dr_struct()){
         fprintf(stderr, "Error initializing protocol proto_sun_dr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MDQS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mdqs_struct()){
         fprintf(stderr, "Error initializing protocol proto_mdqs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DOOM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_doom_struct()){
         fprintf(stderr, "Error initializing protocol proto_doom");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DISCLOSE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_disclose_struct()){
         fprintf(stderr, "Error initializing protocol proto_disclose");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MECOMM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mecomm_struct()){
         fprintf(stderr, "Error initializing protocol proto_mecomm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MEREGISTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_meregister_struct()){
         fprintf(stderr, "Error initializing protocol proto_meregister");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VACDSM_SWS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vacdsm_sws_struct()){
         fprintf(stderr, "Error initializing protocol proto_vacdsm_sws");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VACDSM_APP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vacdsm_app_struct()){
         fprintf(stderr, "Error initializing protocol proto_vacdsm_app");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VPPS_QUA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vpps_qua_struct()){
         fprintf(stderr, "Error initializing protocol proto_vpps_qua");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CIMPLEX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cimplex_struct()){
         fprintf(stderr, "Error initializing protocol proto_cimplex");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_acap_struct()){
         fprintf(stderr, "Error initializing protocol proto_acap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DCTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dctp_struct()){
         fprintf(stderr, "Error initializing protocol proto_dctp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VPPS_VIA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vpps_via_struct()){
         fprintf(stderr, "Error initializing protocol proto_vpps_via");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vpp_struct()){
         fprintf(stderr, "Error initializing protocol proto_vpp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GGF_NCP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ggf_ncp_struct()){
         fprintf(stderr, "Error initializing protocol proto_ggf_ncp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MRM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mrm_struct()){
         fprintf(stderr, "Error initializing protocol proto_mrm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTRUST_AAAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entrust_aaas_struct()){
         fprintf(stderr, "Error initializing protocol proto_entrust_aaas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTRUST_AAMS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entrust_aams_struct()){
         fprintf(stderr, "Error initializing protocol proto_entrust_aams");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XFR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xfr_struct()){
         fprintf(stderr, "Error initializing protocol proto_xfr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CORBA_IIOP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_corba_iiop_struct()){
         fprintf(stderr, "Error initializing protocol proto_corba_iiop");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CORBA_IIOP_SSL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_corba_iiop_ssl_struct()){
         fprintf(stderr, "Error initializing protocol proto_corba_iiop_ssl");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MDC_PORTMAPPER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mdc_portmapper_struct()){
         fprintf(stderr, "Error initializing protocol proto_mdc_portmapper");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HCP_WISMAR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hcp_wismar_struct()){
         fprintf(stderr, "Error initializing protocol proto_hcp_wismar");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ASIPREGISTRY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_asipregistry_struct()){
         fprintf(stderr, "Error initializing protocol proto_asipregistry");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_REALM_RUSD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_realm_rusd_struct()){
         fprintf(stderr, "Error initializing protocol proto_realm_rusd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NMAP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nmap_struct()){
         fprintf(stderr, "Error initializing protocol proto_nmap");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VATP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vatp_struct()){
         fprintf(stderr, "Error initializing protocol proto_vatp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MSEXCH_ROUTING //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_msexch_routing_struct()){
         fprintf(stderr, "Error initializing protocol proto_msexch_routing");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HYPERWAVE_ISP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_hyperwave_isp_struct()){
         fprintf(stderr, "Error initializing protocol proto_hyperwave_isp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CONNENDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_connendp_struct()){
         fprintf(stderr, "Error initializing protocol proto_connendp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_HA_CLUSTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ha_cluster_struct()){
         fprintf(stderr, "Error initializing protocol proto_ha_cluster");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IEEE_MMS_SSL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ieee_mms_ssl_struct()){
         fprintf(stderr, "Error initializing protocol proto_ieee_mms_ssl");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RUSHD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rushd_struct()){
         fprintf(stderr, "Error initializing protocol proto_rushd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_UUIDGEN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_uuidgen_struct()){
         fprintf(stderr, "Error initializing protocol proto_uuidgen");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OLSR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_olsr_struct()){
         fprintf(stderr, "Error initializing protocol proto_olsr");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACCESSNETWORK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_accessnetwork_struct()){
         fprintf(stderr, "Error initializing protocol proto_accessnetwork");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EPP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_epp_struct()){
         fprintf(stderr, "Error initializing protocol proto_epp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_lmp_struct()){
         fprintf(stderr, "Error initializing protocol proto_lmp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRIS_BEEP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iris_beep_struct()){
         fprintf(stderr, "Error initializing protocol proto_iris_beep");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ELCSD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_elcsd_struct()){
         fprintf(stderr, "Error initializing protocol proto_elcsd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_AGENTX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_agentx_struct()){
         fprintf(stderr, "Error initializing protocol proto_agentx");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SILC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_silc_struct()){
         fprintf(stderr, "Error initializing protocol proto_silc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BORLAND_DSJ //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_borland_dsj_struct()){
         fprintf(stderr, "Error initializing protocol proto_borland_dsj");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTRUST_KMSH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entrust_kmsh_struct()){
         fprintf(stderr, "Error initializing protocol proto_entrust_kmsh");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTRUST_ASH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entrust_ash_struct()){
         fprintf(stderr, "Error initializing protocol proto_entrust_ash");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CISCO_TDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cisco_tdp_struct()){
         fprintf(stderr, "Error initializing protocol proto_cisco_tdp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TBRPF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tbrpf_struct()){
         fprintf(stderr, "Error initializing protocol proto_tbrpf");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRIS_XPC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iris_xpc_struct()){
         fprintf(stderr, "Error initializing protocol proto_iris_xpc");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRIS_XPCS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iris_xpcs_struct()){
         fprintf(stderr, "Error initializing protocol proto_iris_xpcs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IRIS_LWZ //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iris_lwz_struct()){
         fprintf(stderr, "Error initializing protocol proto_iris_lwz");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PANA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pana_struct()){
         fprintf(stderr, "Error initializing protocol proto_pana");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETVIEWDM1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netviewdm1_struct()){
         fprintf(stderr, "Error initializing protocol proto_netviewdm1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETVIEWDM2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netviewdm2_struct()){
         fprintf(stderr, "Error initializing protocol proto_netviewdm2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETVIEWDM3 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netviewdm3_struct()){
         fprintf(stderr, "Error initializing protocol proto_netviewdm3");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETGW //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netgw_struct()){
         fprintf(stderr, "Error initializing protocol proto_netgw");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETRCS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netrcs_struct()){
         fprintf(stderr, "Error initializing protocol proto_netrcs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FLEXLM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_flexlm_struct()){
         fprintf(stderr, "Error initializing protocol proto_flexlm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FUJITSU_DEV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_fujitsu_dev_struct()){
         fprintf(stderr, "Error initializing protocol proto_fujitsu_dev");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RIS_CM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ris_cm_struct()){
         fprintf(stderr, "Error initializing protocol proto_ris_cm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KERBEROS_ADM //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_kerberos_adm_struct()){
         fprintf(stderr, "Error initializing protocol proto_kerberos_adm");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RFILE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rfile_struct()){
         fprintf(stderr, "Error initializing protocol proto_rfile");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_LOADAV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_loadav_struct()){
         fprintf(stderr, "Error initializing protocol proto_loadav");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KERBEROS_IV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_kerberos_iv_struct()){
         fprintf(stderr, "Error initializing protocol proto_kerberos_iv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PUMP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pump_struct()){
         fprintf(stderr, "Error initializing protocol proto_pump");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QRH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_qrh_struct()){
         fprintf(stderr, "Error initializing protocol proto_qrh");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RRH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rrh_struct()){
         fprintf(stderr, "Error initializing protocol proto_rrh");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TELL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_tell_struct()){
         fprintf(stderr, "Error initializing protocol proto_tell");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NLOGIN //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nlogin_struct()){
         fprintf(stderr, "Error initializing protocol proto_nlogin");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CON //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_con_struct()){
         fprintf(stderr, "Error initializing protocol proto_con");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ns_struct()){
         fprintf(stderr, "Error initializing protocol proto_ns");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RXE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rxe_struct()){
         fprintf(stderr, "Error initializing protocol proto_rxe");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_QUOTAD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_quotad_struct()){
         fprintf(stderr, "Error initializing protocol proto_quotad");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CYCLESERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cycleserv_struct()){
         fprintf(stderr, "Error initializing protocol proto_cycleserv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OMSERV //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_omserv_struct()){
         fprintf(stderr, "Error initializing protocol proto_omserv");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WEBSTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_webster_struct()){
         fprintf(stderr, "Error initializing protocol proto_webster");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PHONEBOOK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_phonebook_struct()){
         fprintf(stderr, "Error initializing protocol proto_phonebook");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VID //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vid_struct()){
         fprintf(stderr, "Error initializing protocol proto_vid");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CADLOCK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cadlock_struct()){
         fprintf(stderr, "Error initializing protocol proto_cadlock");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RTIP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rtip_struct()){
         fprintf(stderr, "Error initializing protocol proto_rtip");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CYCLESERV2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cycleserv2_struct()){
         fprintf(stderr, "Error initializing protocol proto_cycleserv2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SUBMIT //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_submit_struct()){
         fprintf(stderr, "Error initializing protocol proto_submit");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NOTIFY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_notify_struct()){
         fprintf(stderr, "Error initializing protocol proto_notify");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RPASSWD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rpasswd_struct()){
         fprintf(stderr, "Error initializing protocol proto_rpasswd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACMAINT_DBD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_acmaint_dbd_struct()){
         fprintf(stderr, "Error initializing protocol proto_acmaint_dbd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ENTOMB //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_entomb_struct()){
         fprintf(stderr, "Error initializing protocol proto_entomb");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACMAINT_TRANSD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_acmaint_transd_struct()){
         fprintf(stderr, "Error initializing protocol proto_acmaint_transd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WPAGES //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_wpages_struct()){
         fprintf(stderr, "Error initializing protocol proto_wpages");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MULTILING_HTTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_multiling_http_struct()){
         fprintf(stderr, "Error initializing protocol proto_multiling_http");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_WPGS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_wpgs_struct()){
         fprintf(stderr, "Error initializing protocol proto_wpgs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MDBS_DAEMON //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mdbs_daemon_struct()){
         fprintf(stderr, "Error initializing protocol proto_mdbs_daemon");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DEVICE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_device_struct()){
         fprintf(stderr, "Error initializing protocol proto_device");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MBAP_S //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_mbap_s_struct()){
         fprintf(stderr, "Error initializing protocol proto_mbap_s");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FCP_UDP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_fcp_udp_struct()){
         fprintf(stderr, "Error initializing protocol proto_fcp_udp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ITM_MCELL_S //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_itm_mcell_s_struct()){
         fprintf(stderr, "Error initializing protocol proto_itm_mcell_s");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PKIX_3_CA_RA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pkix_3_ca_ra_struct()){
         fprintf(stderr, "Error initializing protocol proto_pkix_3_ca_ra");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETCONF_SSH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netconf_ssh_struct()){
         fprintf(stderr, "Error initializing protocol proto_netconf_ssh");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETCONF_BEEP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netconf_beep_struct()){
         fprintf(stderr, "Error initializing protocol proto_netconf_beep");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETCONFSOAPHTTP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netconfsoaphttp_struct()){
         fprintf(stderr, "Error initializing protocol proto_netconfsoaphttp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NETCONFSOAPBEEP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_netconfsoapbeep_struct()){
         fprintf(stderr, "Error initializing protocol proto_netconfsoapbeep");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DHCP_FAILOVER2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_dhcp_failover2_struct()){
         fprintf(stderr, "Error initializing protocol proto_dhcp_failover2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GDOI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_gdoi_struct()){
         fprintf(stderr, "Error initializing protocol proto_gdoi");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_DOMAIN_S //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_domain_s_struct()){
         fprintf(stderr, "Error initializing protocol proto_domain_s");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ISCSI //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iscsi_struct()){
         fprintf(stderr, "Error initializing protocol proto_iscsi");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OWAMP_CONTROL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_owamp_control_struct()){
         fprintf(stderr, "Error initializing protocol proto_owamp_control");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TWAMP_CONTROL //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_twamp_control_struct()){
         fprintf(stderr, "Error initializing protocol proto_twamp_control");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_RSYNC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_rsync_struct()){
         fprintf(stderr, "Error initializing protocol proto_rsync");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ICLCNET_LOCATE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iclcnet_locate_struct()){
         fprintf(stderr, "Error initializing protocol proto_iclcnet_locate");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ICLCNET_SVINFO //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_iclcnet_svinfo_struct()){
         fprintf(stderr, "Error initializing protocol proto_iclcnet_svinfo");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_ACCESSBUILDER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_accessbuilder_struct()){
         fprintf(stderr, "Error initializing protocol proto_accessbuilder");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CDDBP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cddbp_struct()){
         fprintf(stderr, "Error initializing protocol proto_cddbp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_OMGINITIALREFS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_omginitialrefs_struct()){
         fprintf(stderr, "Error initializing protocol proto_omginitialrefs");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SMPNAMERES //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_smpnameres_struct()){
         fprintf(stderr, "Error initializing protocol proto_smpnameres");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDEAFARM_DOOR //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ideafarm_door_struct()){
         fprintf(stderr, "Error initializing protocol proto_ideafarm_door");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_IDEAFARM_PANIC //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ideafarm_panic_struct()){
         fprintf(stderr, "Error initializing protocol proto_ideafarm_panic");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_KINK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_kink_struct()){
         fprintf(stderr, "Error initializing protocol proto_kink");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_XACT_BACKUP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_xact_backup_struct()){
         fprintf(stderr, "Error initializing protocol proto_xact_backup");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_APEX_MESH //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_apex_mesh_struct()){
         fprintf(stderr, "Error initializing protocol proto_apex_mesh");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_APEX_EDGE //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_apex_edge_struct()){
         fprintf(stderr, "Error initializing protocol proto_apex_edge");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FTPS_DATA //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ftps_data_struct()){
         fprintf(stderr, "Error initializing protocol proto_ftps_data");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_FTPS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_ftps_struct()){
         fprintf(stderr, "Error initializing protocol proto_ftps");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_NAS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_nas_struct()){
         fprintf(stderr, "Error initializing protocol proto_nas");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_TELNETS //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_telnets_struct()){
         fprintf(stderr, "Error initializing protocol proto_telnets");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_POP3S //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_pop3s_struct()){
         fprintf(stderr, "Error initializing protocol proto_pop3s");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_VSINET //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_vsinet_struct()){
         fprintf(stderr, "Error initializing protocol proto_vsinet");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_MAITRD //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_maitrd_struct()){
         fprintf(stderr, "Error initializing protocol proto_maitrd");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BUSBOY //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_busboy_struct()){
         fprintf(stderr, "Error initializing protocol proto_busboy");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PUPARP //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_puparp_struct()){
         fprintf(stderr, "Error initializing protocol proto_puparp");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_GARCON //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_garcon_struct()){
         fprintf(stderr, "Error initializing protocol proto_garcon");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_APPLIX //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_applix_struct()){
         fprintf(stderr, "Error initializing protocol proto_applix");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_PUPROUTER //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_puprouter_struct()){
         fprintf(stderr, "Error initializing protocol proto_puprouter");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_CADLOCK2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_cadlock2_struct()){
         fprintf(stderr, "Error initializing protocol proto_cadlock2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_SURF //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_surf_struct()){
         fprintf(stderr, "Error initializing protocol proto_surf");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EXP1 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_exp1_struct()){
         fprintf(stderr, "Error initializing protocol proto_exp1");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_EXP2 //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_exp2_struct()){
         fprintf(stderr, "Error initializing protocol proto_exp2");
         exit(0);
    }

    /////////////////////////////////////////////////
    /////////// INITILIZING PROTO_BLACKJACK //////////////////
    // was generated by MMTCrawler on 08 mar 2016 @luongnv89
    if (!init_proto_blackjack_struct()){
         fprintf(stderr, "Error initializing protocol proto_blackjack");
         exit(0);
    }




    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////END OF GENERATED CODE ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////START OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http, 20);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ssl, 20);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_stun_tcp, 30);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_stun_udp, 30);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rtp_tcp, 50); //Check STUN before RTP
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_rtp_udp, 50); //Check STUN before RTP
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_rdp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_sip, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sip, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_bittorrent_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_bittorrent_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_edonkey, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_edonkey, 50); //BW: TODO: Edonkey classification seems limited to TCP! Check this out
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_fasttrack, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_gnutella, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gnutella, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_winmx, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_directconnect_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_directconnect_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_msn_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_msn_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_yahoo_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_yahoo_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_oscar, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_oscar, 50); //BW: TODO: the calssification of oscar seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_applejuice, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_soulseek, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_irc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_jabber, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_jabber, 50); //BW: TODO: the calssification of jabber seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pop, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_imap, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_smtp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ftp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ndn, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_usenet, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dns, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dns, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_filetopia, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_manolito_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_manolito_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_imesh_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_imesh_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mms, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pando, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pando, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tvants_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tvants_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_sopcast_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sopcast_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tvuplayer_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tvuplayer_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ppstream_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ppstream_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pplive_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pplive_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_iax, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_mgcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_gadugadu, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_gadugadu, 50); //BW: TODO: the calssification of gadugadu seems to be for TCP only
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_zattoo_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_zattoo_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_qq_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_qq_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_feidian_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_feidian_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ssh, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_popo, 50); //BW: TODO: check this out
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_popo, 50); //BW: TODO: check this out
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_thunder_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_thunder_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_vnc, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_teamviewer_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_teamviewer_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dhcp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_i23v5, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_socrates_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_socrates_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_steam, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_halflife2, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_xbox, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_xbox, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_http_application_activesync, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_smb, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_telnet, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ntp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_nfs, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_nfs, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ssdp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_worldofwarcraft, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_flash, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_postgres, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mysql, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_bgp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_quake, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_battlefield, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_secondlife_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_secondlife_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pcanywhere, 50); //BW: TODO: The classification of PCANYWHERE seems to be for UDP only, check this out
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_pcanywhere, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_snmp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_kontiki, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_icecast, 50); //BW: TODO: Check out the classification --- dependence on http
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_shoutcast, 50); //BW: TODO: Check out the classification --- dependence on http
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_veohtv_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_veohtv_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_kerberos, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_openft, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_syslog, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_syslog, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_tds, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_direct_download_link, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_netbios_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_netbios_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_mdns, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ipp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ipp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_ldap, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_ldap, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_warcraft3, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_warcraft3, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_xdmcp_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_xdmcp_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_tftp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_mssql, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_pptp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_stealthnet, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dhcpv6, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_meebo, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_afp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_aimini_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_aimini_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_florensia_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_florensia_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_maplestory, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dofus, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_world_of_kung_fu, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_fiesta, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_crossfire_tcp, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_crossfire_udp, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_guildwars, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_armagetron, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_dropbox_udp, 50);
    // register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_skype_tcp, 60);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_skype_udp, 60);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_radius, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_citrix, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_dcerpc, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_netflow, 50);
    register_classification_function_with_parent_protocol(PROTO_UDP, mmt_check_sflow, 50);
    register_classification_function_with_parent_protocol(PROTO_TCP, mmt_check_spotify, 50);
    ///////////////////////////////////////////////////////////////////////////////////////
    /////////////////////END OF INTER-PROTOCOL CLASSIFICATIONS ////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////

    return retval;
}

