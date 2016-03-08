#ifndef MMT_TCPIP_PROTOCOLS
#define MMT_TCPIP_PROTOCOLS

#ifdef __cplusplus
extern "C" {
#endif

#include "mmt_contents_defs.h"
#include "mmt_tcpip_attributes.h"

#define MMT_SUPPORT_IPV6
#define PROTOCOL_HISTORY_SIZE 3

//#define PROTO_UNKNOWN 0 //Already defined in the core
//#define PROTO_META    1 //Already defined in the core
#define PROTO_163 2
#define PROTO_360 3
#define PROTO_302_FOUND 4
#define PROTO_360BUY 5
#define PROTO_56 6
#define PROTO_8021Q 7
#define PROTO_888 8
#define PROTO_ABOUT 9
#define PROTO_ADCASH 10
#define PROTO_ADDTHIS 11
#define PROTO_ADF 12
#define PROTO_ADOBE 13
#define PROTO_AFP 14
#define PROTO_AH 15
#define PROTO_AIM 16
#define PROTO_AIMINI 17
#define PROTO_ALIBABA 18
#define PROTO_ALIPAY 19
#define PROTO_ALLEGRO 20
#define PROTO_AMAZON 21
#define PROTO_AMEBLO 22
#define PROTO_ANCESTRY 23
#define PROTO_ANGRYBIRDS 24
#define PROTO_ANSWERS 25
#define PROTO_AOL 26
#define PROTO_APPLE 27
#define PROTO_APPLEJUICE 28
#define PROTO_ARMAGETRON 29
#define PROTO_ARP 30
#define PROTO_ASK 31
#define PROTO_AVG 32
#define PROTO_AVI 33
#define PROTO_AWEBER 34
#define PROTO_AWS 35
#define PROTO_BABYLON 36
#define PROTO_BADOO 37
#define PROTO_BAIDU 38
#define PROTO_BANKOFAMERICA 39
#define PROTO_BARNESANDNOBLE 40
#define PROTO_BATMAN 41
#define PROTO_BATTLEFIELD 42
#define PROTO_BATTLENET 43
#define PROTO_BBB 44
#define PROTO_BBC_ONLINE 45
#define PROTO_BESTBUY 46
#define PROTO_BETFAIR 47
#define PROTO_BGP 48
#define PROTO_BIBLEGATEWAY 49
#define PROTO_BILD 50
#define PROTO_BING 51
#define PROTO_BITTORRENT 52
#define PROTO_BLEACHERREPORT 53
#define PROTO_BLOGFA 54
#define PROTO_BLOGGER 55
#define PROTO_BLOGSPOT 56
#define PROTO_BODYBUILDING 57
#define PROTO_BOOKING 58
#define PROTO_CBSSPORTS 59
#define PROTO_CENT 60
#define PROTO_CHANGE 61
#define PROTO_CHASE 62
#define PROTO_CHESS 63
#define PROTO_CHINAZ 64
#define PROTO_CITRIX 65
#define PROTO_CITRIXONLINE 66
#define PROTO_CLICKSOR 67
#define PROTO_CNN 68
#define PROTO_CNZZ 69
#define PROTO_COMCAST 70
#define PROTO_CONDUIT 71
#define PROTO_COPYSCAPE 72
#define PROTO_CORREIOS 73
#define PROTO_CRAIGSLIST 74
#define PROTO_CROSSFIRE 75
#define PROTO_DAILYMAIL 76
#define PROTO_DAILYMOTION 77
#define PROTO_DCERPC 78
#define PROTO_DIRECT_DOWNLOAD_LINK 79
#define PROTO_DEVIANTART 80
#define PROTO_DHCP 81
#define PROTO_DHCPV6 82
#define PROTO_DIGG 83
#define PROTO_DIRECTCONNECT 84
#define PROTO_DNS 85
#define PROTO_DOFUS 86
#define PROTO_DONANIMHABER 87
#define PROTO_DOUBAN 88
#define PROTO_DOUBLECLICK 89
#define PROTO_DROPBOX 90
#define PROTO_EBAY 91
#define PROTO_EDONKEY 92
#define PROTO_EGP 93
#define PROTO_EHOW 94
#define PROTO_EKSISOZLUK 95
#define PROTO_ELECTRONICSARTS 96
#define PROTO_ESP 97
#define PROTO_ESPN 98
#define PROTO_ETHERNET 99
#define PROTO_ETSY 100
#define PROTO_EUROPA 101
#define PROTO_EUROSPORT 102
#define PROTO_FACEBOOK 103
#define PROTO_FACETIME 104
#define PROTO_FASTTRACK 105
#define PROTO_FC2 106
#define PROTO_FEIDIAN 107
#define PROTO_FIESTA 108
#define PROTO_FILETOPIA 109
#define PROTO_FIVERR 110
#define PROTO_FLASH 111
#define PROTO_FLICKR 112
#define PROTO_FLORENSIA 113
#define PROTO_FOURSQUARE 114
#define PROTO_FOX 115
#define PROTO_FREE 116
#define PROTO_FTP 117
#define PROTO_GADUGADU 118
#define PROTO_GAMEFAQS 119
#define PROTO_GAMESPOT 120
#define PROTO_GAP 121
#define PROTO_GARANTI 122
#define PROTO_GAZETEVATAN 123
#define PROTO_GIGAPETA 124
#define PROTO_GITHUB 125
#define PROTO_GITTIGIDIYOR 126
#define PROTO_GLOBO 127
#define PROTO_GMAIL 128
#define PROTO_GNUTELLA 129
#define PROTO_GOOGLE_MAPS 130
#define PROTO_GO 131
#define PROTO_GODADDY 132
#define PROTO_GOO 133
#define PROTO_GOOGLE 134
#define PROTO_GOOGLE_USER_CONTENT 135
#define PROTO_GOSMS 136
#define PROTO_GRE 137
#define PROTO_GROOVESHARK 138
#define PROTO_GROUPON 139
#define PROTO_GTALK 140
#define PROTO_GTP 141
#define PROTO_GTP2 142
#define PROTO_GUARDIAN 143
#define PROTO_GUILDWARS 144
#define PROTO_HABERTURK 145
#define PROTO_HAO123 146
#define PROTO_HEPSIBURADA 147
#define PROTO_HI5 148
#define PROTO_HALFLIFE2 149
#define PROTO_HOMEDEPOT 150
#define PROTO_HOOTSUITE 151
#define PROTO_HOTMAIL 152
#define PROTO_HTTP 153
#define PROTO_HTTP_CONNECT 154
#define PROTO_HTTP_PROXY 155
#define PROTO_HTTP_APPLICATION_ACTIVESYNC 156
#define PROTO_HUFFINGTON_POST 157
#define PROTO_HURRIYET 158
#define PROTO_I23V5 159
#define PROTO_IAX 160
#define PROTO_ICECAST 161
#define PROTO_APPLE_ICLOUD 162
#define PROTO_ICMP 163
#define PROTO_ICMPV6 164
#define PROTO_IFENG 165
#define PROTO_IGMP 166
#define PROTO_IGN 167
#define PROTO_IKEA 168
#define PROTO_IMAP 169
#define PROTO_IMAPS 170
#define PROTO_INTERNET_MOVIE_DATABASE 171
#define PROTO_IMESH 172
#define PROTO_IMESSAGE 173
#define PROTO_IMGUR 174
#define PROTO_INCREDIBAR 175
#define PROTO_INDIATIMES 176
#define PROTO_INSTAGRAM 177
#define PROTO_IP 178
#define PROTO_IP_IN_IP 179
#define PROTO_IPP 180
#define PROTO_IPSEC 181
#define PROTO_IPV6 182
#define PROTO_IRC 183
#define PROTO_IRS 184
#define PROTO_APPLE_ITUNES 185
#define PROTO_UNENCRYPED_JABBER 186
#define PROTO_JAPANPOST 187
#define PROTO_KAKAO 188
#define PROTO_KAT 189
#define PROTO_KAZAA 190
#define PROTO_KERBEROS 191
#define PROTO_KING 192
#define PROTO_KOHLS 193
#define PROTO_KONGREGATE 194
#define PROTO_KONTIKI 195
#define PROTO_L2TP 196
#define PROTO_LASTFM 197
#define PROTO_LDAP 198
#define PROTO_LEAGUEOFLEGENDS 199
#define PROTO_LEGACY 200
#define PROTO_LETV 201
#define PROTO_LINKEDIN 202
#define PROTO_LIVE 203
#define PROTO_LIVEDOOR 204
#define PROTO_LIVEMAIL 205
#define PROTO_LIVEINTERNET 206
#define PROTO_LIVEJASMIN 207
#define PROTO_LIVEJOURNAL 208
#define PROTO_LIVESCORE 209
#define PROTO_LIVINGSOCIAL 210
#define PROTO_LOWES 211
#define PROTO_MACYS 212
#define PROTO_MAIL_RU 213
#define PROTO_MANET 214
#define PROTO_MANOLITO 215
#define PROTO_MAPLESTORY 216
#define PROTO_MATCH 217
#define PROTO_MDNS 218
#define PROTO_MEDIAFIRE 219
#define PROTO_MEEBO 220
#define PROTO_MGCP 221
#define PROTO_MICROSOFT 222
#define PROTO_MILLIYET 223
#define PROTO_MINECRAFT 224
#define PROTO_MINICLIP 225
#define PROTO_MLBASEBALL 226
#define PROTO_MMO_CHAMPION 227
#define PROTO_MMS 228
#define PROTO_MOVE 229
#define PROTO_MOZILLA 230
#define PROTO_MPEG 231
#define PROTO_MSN 232
#define PROTO_MSSQL 233
#define PROTO_MULTIPLY 234
#define PROTO_MYNET 235
#define PROTO_MYSPACE 236
#define PROTO_MYSQL 237
#define PROTO_MYWEBSEARCH 238
#define PROTO_NBA 239
#define PROTO_NEOBUX 240
#define PROTO_NETBIOS 241
#define PROTO_NETFLIX 242
#define PROTO_NETFLOW 243
#define PROTO_NEWEGG 244
#define PROTO_NEWSMAX 245
#define PROTO_NFL 246
#define PROTO_NFS 247
#define PROTO_NICOVIDEO 248
#define PROTO_NIH 249
#define PROTO_NORDSTROM 250
#define PROTO_NTP 251
#define PROTO_NYTIMES 252
#define PROTO_ODNOKLASSNIKI 253
#define PROTO_OFF 254
#define PROTO_OGG 255
#define PROTO_ONET 256
#define PROTO_OPENFT 257
#define PROTO_ORANGEDONKEY 258
#define PROTO_OSCAR 259
#define PROTO_OSPF 260
#define PROTO_OUTBRAIN 261
#define PROTO_OVERSTOCK 262
#define PROTO_PANDO 263
#define PROTO_PAYPAL 264
#define PROTO_PCANYWHERE 265
#define PROTO_PCH 266
#define PROTO_PCONLINE 267
#define PROTO_PHOTOBUCKET 268
#define PROTO_PINTEREST 269
#define PROTO_PLAYSTATION 270
#define PROTO_POGO 271
#define PROTO_POP 272
#define PROTO_POPS 273
#define PROTO_POPO 274
#define PROTO_PORNHUB 275
#define PROTO_POSTGRES 276
#define PROTO_PPLIVE 277
#define PROTO_PPP 278
#define PROTO_PPPOE 279
#define PROTO_PPSTREAM 280
#define PROTO_PPTP 281
#define PROTO_PREMIERLEAGUE 282
#define PROTO_QQ 283
#define PROTO_QQLIVE 284
#define PROTO_QUAKE 285
#define PROTO_QUICKTIME 286
#define PROTO_R10 287
#define PROTO_RADIUS 288
#define PROTO_RAKUTEN 289
#define PROTO_RDP 290
#define PROTO_REALMEDIA 291
#define PROTO_REDDIT 292
#define PROTO_REDTUBE 293
#define PROTO_REFERENCE 294
#define PROTO_RENREN 295
#define PROTO_ROBLOX 296
#define PROTO_ROVIO 297
#define PROTO_RTP 298
#define PROTO_RTSP 299
#define PROTO_SABAHTR 300
#define PROTO_SAHIBINDEN 301
#define PROTO_SALESFORCE 302
#define PROTO_SALON 303
#define PROTO_SCTP 304
#define PROTO_SEARCHNU 305
#define PROTO_SEARCH_RESULTS 306
#define PROTO_SEARS 307
#define PROTO_SECONDLIFE 308
#define PROTO_SECURESERVER 309
#define PROTO_SFLOW 310
#define PROTO_SHAZAM 311
#define PROTO_SHOUTCAST 312
#define PROTO_SINA 313
#define PROTO_SIP 314
#define PROTO_SITEADVISOR 315
#define PROTO_SKY 316
#define PROTO_SKYPE 317
#define PROTO_SKYROCK 318
#define PROTO_SKYSPORTS 319
#define PROTO_SLATE 320
#define PROTO_SLIDESHARE 321
#define PROTO_SMB 322
#define PROTO_SMTP 323
#define PROTO_SMTPS 324
#define PROTO_SNMP 325
#define PROTO_SOCRATES 326
#define PROTO_SOFTONIC 327
#define PROTO_SOGOU 328
#define PROTO_SOHU 329
#define PROTO_SOPCAST 330
#define PROTO_SOSO 331
#define PROTO_SOULSEEK 332
#define PROTO_SOUNDCLOUD 333
#define PROTO_SOURGEFORGE 334
#define PROTO_SPIEGEL 335
#define PROTO_SPORX 336
#define PROTO_SPOTIFY 337
#define PROTO_SQUIDOO 338
#define PROTO_SSDP 339
#define PROTO_SSH 340
#define PROTO_SSL 341
#define PROTO_STACK_OVERFLOW 342
#define PROTO_STATCOUNTER 343
#define PROTO_STEALTHNET 344
#define PROTO_STEAM 345
#define PROTO_STUMBLEUPON 346
#define PROTO_STUN 347
#define PROTO_SULEKHA 348
#define PROTO_SYSLOG 349
#define PROTO_TAGGED 350
#define PROTO_TAOBAO 351
#define PROTO_TARGET 352
#define PROTO_TCO 353
#define PROTO_TCP 354
#define PROTO_TDS 355
#define PROTO_TEAMVIEWER 356
#define PROTO_TELNET 357
#define PROTO_TFTP 358
#define PROTO_THEMEFOREST 359
#define PROTO_THE_PIRATE_BAY 360
#define PROTO_THUNDER 361
#define PROTO_TIANYA 362
#define PROTO_TLS 363
#define PROTO_TMALL 364
#define PROTO_TORRENTZ 365
#define PROTO_TRUPHONE 366
#define PROTO_TUBE8 367
#define PROTO_TUDOU 368
#define PROTO_TUENTI 369
#define PROTO_TUMBLR 370
#define PROTO_TVANTS 371
#define PROTO_TVUPLAYER 372
#define PROTO_TWITTER 373
#define PROTO_UBI 374
#define PROTO_UCOZ 375
#define PROTO_UDP 376
#define PROTO_UDPLITE 377
#define PROTO_UOL 378
#define PROTO_USDEPARTMENTOFSTATE 379
#define PROTO_USENET 380
#define PROTO_USTREAM 381
#define PROTO_HTTP_APPLICATION_VEOHTV 382
#define PROTO_VIADEO 383
#define PROTO_VIBER 384
#define PROTO_VIMEO 385
#define PROTO_VK 386
#define PROTO_VKONTAKTE 387
#define PROTO_VNC 388
#define PROTO_WALMART 389
#define PROTO_WARRIORFORUM 390
#define PROTO_WAYN 391
#define PROTO_WEATHER 392
#define PROTO_WEBEX 393
#define PROTO_WEEKLYSTANDARD 394
#define PROTO_WEIBO 395
#define PROTO_WELLSFARGO 396
#define PROTO_WHATSAPP 397
#define PROTO_WIGETMEDIA 398
#define PROTO_WIKIA 399
#define PROTO_WIKIMEDIA 400
#define PROTO_WIKIPEDIA 401
#define PROTO_WILLIAMHILL 402
#define PROTO_WINDOWSLIVE 403
#define PROTO_WINDOWSMEDIA 404
#define PROTO_WINMX 405
#define PROTO_WINUPDATE 406
#define PROTO_WORLD_OF_KUNG_FU 407
#define PROTO_WORDPRESS_ORG 408
#define PROTO_WARCRAFT3 409
#define PROTO_WORLDOFWARCRAFT 410
#define PROTO_WOWHEAD 411
#define PROTO_WWE 412
#define PROTO_XBOX 413
#define PROTO_XDMCP 414
#define PROTO_XHAMSTER 415
#define PROTO_XING 416
#define PROTO_XINHUANET 417
#define PROTO_XNXX 418
#define PROTO_XVIDEOS 419
#define PROTO_YAHOO 420
#define PROTO_YAHOOGAMES 421
#define PROTO_YAHOOMAIL 422
#define PROTO_YANDEX 423
#define PROTO_YELP 424
#define PROTO_YOUKU 425
#define PROTO_YOUPORN 426
#define PROTO_YOUTUBE 427
#define PROTO_ZAPPOS 428
#define PROTO_ZATTOO 429
#define PROTO_ZEDO 430
#define PROTO_ZOL 431
#define PROTO_ZYNGA 432
#define PROTO_3PC 433
#define PROTO_ANY_0HOP 434
#define PROTO_ANY_DFS 435
#define PROTO_ANY_HIP 436
#define PROTO_ANY_LOCAL 437
#define PROTO_ANY_PES 438
#define PROTO_ARGUS 439
#define PROTO_ARIS 440
#define PROTO_AX_25 441
#define PROTO_BBN_RCC_MON 442
#define PROTO_BNA 443
#define PROTO_BR_SAT_MON 444
#define PROTO_CBT 445
#define PROTO_CFTP 446
#define PROTO_CHAOS 447
#define PROTO_COMPAQ_PEER 448
#define PROTO_CPHB 449
#define PROTO_CPNX 450
#define PROTO_CRTP 451
#define PROTO_CRUDP 452
#define PROTO_DCCP 453
#define PROTO_DCN_MEAS 454
#define PROTO_DDP 455
#define PROTO_DDX 456
#define PROTO_DGP 457
#define PROTO_EIGRP 458
#define PROTO_EMCON 459
#define PROTO_ENCAP 460
#define PROTO_ETHERIP 461
#define PROTO_FC 462
#define PROTO_FIRE 463
#define PROTO_GGP 464
#define PROTO_GMTP 465
#define PROTO_HIP 466
#define PROTO_HMP 467
#define PROTO_I_NLSP 468
#define PROTO_IATP 469
#define PROTO_IDPR 470
#define PROTO_IDPR_CMTP 471
#define PROTO_IDRP 472
#define PROTO_IFMP 473
#define PROTO_IGP 474
#define PROTO_IL 475
#define PROTO_IPCOMP 476
#define PROTO_IPCV 477
#define PROTO_IPLT 478
#define PROTO_IPPC 479
#define PROTO_IPTM 480
#define PROTO_IPX_IN_IP 481
#define PROTO_IRTP 482
#define PROTO_IS_IS 483
#define PROTO_ISO_IP 484
#define PROTO_ISO_TP4 485
#define PROTO_KRYPTOLAN 486
#define PROTO_LARP 487
#define PROTO_LEAF_1 488
#define PROTO_LEAF_2 489
#define PROTO_MERIT_INP 490
#define PROTO_MFE_NSP 491
#define PROTO_MHRP 492
#define PROTO_MICP 493
#define PROTO_MOBILE 494
#define PROTO_MOBILITY_HEADER 495
#define PROTO_MPLS_IN_IP 496
#define PROTO_MTP 497
#define PROTO_MUX 498
#define PROTO_NARP 499
#define PROTO_NETBLT 500
#define PROTO_NSFNET_IGP 501
#define PROTO_NVP_II 502
#define PROTO_PGM 503
#define PROTO_PIM 504
#define PROTO_PIPE 505
#define PROTO_PNNI 506
#define PROTO_PRM 507
#define PROTO_PTP 508
#define PROTO_PUP 509
#define PROTO_PVP 510
#define PROTO_QNX 511
#define PROTO_RSVP 512
#define PROTO_RSVP_E2E_IGNORE 513
#define PROTO_RVD 514
#define PROTO_SAT_EXPAK 515
#define PROTO_SAT_MON 516
#define PROTO_SCC_SP 517
#define PROTO_SCPS 518
#define PROTO_SDRP 519
#define PROTO_SECURE_VMTP 520
#define PROTO_SHIM6 521
#define PROTO_SKIP 522
#define PROTO_SM 523
#define PROTO_SMP 524
#define PROTO_SNP 525
#define PROTO_SPRITE_RPC 526
#define PROTO_SPS 527
#define PROTO_SRP 528
#define PROTO_SSCOPMCE 529
#define PROTO_ST 530
#define PROTO_STP 531
#define PROTO_SUN_ND 532
#define PROTO_SWIPE 533
#define PROTO_TCF 534
#define PROTO_TLSP 535
#define PROTO_TP_PP 536
#define PROTO_TRUNK_1 537
#define PROTO_TRUNK_2 538
#define PROTO_UTI 539
#define PROTO_VINES 540
#define PROTO_VISA 541
#define PROTO_VMTP 542
#define PROTO_VRRP 543
#define PROTO_WB_EXPAK 544
#define PROTO_WB_MON 545
#define PROTO_WSN 546
#define PROTO_XNET 547
#define PROTO_XNS_IDP 548
#define PROTO_XTP 549
#define PROTO_BUZZNET 550
#define PROTO_COMEDY 551
#define PROTO_RAMBLER 552
#define PROTO_SMUGMUG 553
#define PROTO_ARCHIEVE 554
#define PROTO_CITYNEWS 555
#define PROTO_SCIENCESTAGE 556
#define PROTO_ONEWORLD 557
#define PROTO_DISQUS 558
#define PROTO_BLOGCU 559
#define PROTO_EKOLEY 560
#define PROTO_500PX 561
#define PROTO_FOTKI 562
#define PROTO_FOTOLOG 563
#define PROTO_JALBUM 564
#define PROTO_LOCKERZ 565
#define PROTO_PANORAMIO 566
#define PROTO_SNAPFISH 567
#define PROTO_WEBSHOTS 568
#define PROTO_MEGA 569
#define PROTO_VIDOOSH 570
#define PROTO_AFREECA 571
#define PROTO_WILDSCREEN 572
#define PROTO_BLOGTV 573
#define PROTO_HULU 574
#define PROTO_MEVIO 575
#define PROTO_LIVESTREAM 576
#define PROTO_LIVELEAK 577
#define PROTO_DEEZER 578
#define PROTO_BLIPTV 579
#define PROTO_BREAK 580
#define PROTO_CITYTV 581
#define PROTO_COMEDYCENTRAL 582
#define PROTO_ENGAGEMEDIA 583
#define PROTO_SCREENJUNKIES 584
#define PROTO_RUTUBE 585
#define PROTO_SEVENLOAD 586
#define PROTO_MUBI 587
#define PROTO_IZLESENE 588
#define PROTO_VIDEO_HOSTING 589
#define PROTO_BOX 590
#define PROTO_SKYDRIVE 591
#define PROTO_7DIGITAL 592
#define PROTO_CLOUDFRONT 593
#define PROTO_TANGO 594
#define PROTO_WECHAT 595
#define PROTO_LINE 596
#define PROTO_BLOOMBERG 597
#define PROTO_MSCDN 598
#define PROTO_AKAMAI 599
#define PROTO_YAHOOMSG 600
#define PROTO_BITGRAVITY 601
#define PROTO_CACHEFLY 602
#define PROTO_CDN77 603
#define PROTO_CDNETWORKS 604
#define PROTO_CHINACACHE 605
#define PROTO_COTENDO 606
#define PROTO_EDGECAST 607
#define PROTO_FASTLY 608
#define PROTO_HIGHWINDS 609
#define PROTO_INTERNAP 610
#define PROTO_LEVEL3 611
#define PROTO_LIMELIGHT 612
#define PROTO_MAXCDN 613
#define PROTO_NETDNA 614
#define PROTO_VOXEL 615
#define PROTO_RACKSPACE 616
#define PROTO_GAMEFORGE 617
#define PROTO_METIN2 618
#define PROTO_OGAME 619
#define PROTO_BATTLEKNIGHT 620
#define PROTO_4STORY 621
#define PROTO_FBMSG 622 //Facebook messaging
#define PROTO_GCM 623 //Google Cloud Messaging
#define PROTO_SLL 624 //Linux Cooked Socket
#define PROTO_NDN 625 //Linux Cooked Socket
#define PROTO_TCPMUX 626 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMPRESSNET 627 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RJE 628 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ECHO 629 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DISCARD 630 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYSTAT 631 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DAYTIME 632 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QOTD 633 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSP 634 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CHARGEN 635 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTP_DATA 636 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSW_FE 637 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSG_ICP 638 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSG_AUTH 639 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSP 640 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TIME 641 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RAP 642 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RLP 643 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GRAPHICS 644 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAME 645 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAMESERVER 646 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NICNAME 647 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPM_FLAGS 648 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPM 649 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPM_SND 650 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NI_FTP 651 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AUDITD 652 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TACACS 653 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RE_MAIL_CK 654 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_TIME 655 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DOMAIN 656 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_CH 657 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISI_GL 658 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_AUTH 659 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_MAIL 660 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NI_MAIL 661 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACAS 662 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHOISPP 663 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHOIS__ 664 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COVIA 665 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TACACS_DS 666 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQL_NET 667 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQLNET 668 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BOOTPS 669 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BOOTPC 670 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GOPHER 671 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_1 672 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_2 673 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_3 674 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_4 675 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEOS 676 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VETTCP 677 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FINGER 678 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WWW 679 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WWW_HTTP 680 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XFER 681 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MIT_ML_DEV 682 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CTF 683 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MFCOBOL 684 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SU_MIT_TG 685 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PORT 686 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DNSIX 687 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MIT_DOV 688 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPP 689 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DCP 690 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OBJCALL 691 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUPDUP 692 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DIXIE 693 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SWIFT_RVF 694 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TACNEWS 695 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_METAGRAM 696 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HOSTNAME 697 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_TSAP 698 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GPPITNP 699 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACR_NEMA 700 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CSO 701 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CSNET_NS 702 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_3COM_TSMUX 703 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RTELNET 704 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNAGAS 705 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POP2 706 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POP3 707 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUNRPC 708 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MCIDAS 709 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDENT 710 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AUTH 711 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SFTP 712 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ANSANOTIFY 713 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUCP_PATH 714 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQLSERV 715 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NNTP 716 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CFDPTKT 717 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ERPC 718 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMAKYNET 719 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ANSATRADER 720 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOCUS_MAP 721 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NXEDIT 722 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOCUS_CON 723 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GSS_XLICEN 724 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PWDGEN 725 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_FNA 726 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_TNA 727 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_SYS 728 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STATSRV 729 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INGRES_NET 730 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EPMAP 731 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PROFILE 732 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETBIOS_NS 733 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETBIOS_DGM 734 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETBIOS_SSN 735 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EMFIS_DATA 736 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EMFIS_CNTL 737 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BL_IDM 738 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UMA 739 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UAAC 740 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_TP0 741 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_JARGON 742 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AED_512 743 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HEMS 744 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BFTP 745 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SGMP 746 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETSC_PROD 747 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETSC_DEV 748 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQLSRV 749 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KNET_CMP 750 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PCMAIL_SRV 751 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSS_ROUTING 752 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SGMP_TRAPS 753 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNMPTRAP 754 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CMIP_MAN 755 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CMIP_AGENT 756 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_COURIER 757 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_S_NET 758 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAMP 759 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSVD 760 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SEND 761 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRINT_SRV 762 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MULTIPLEX 763 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CL_1 764 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CL1 765 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XYPLEX_MUX 766 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAILQ 767 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VMNET 768 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GENRAD_MUX 769 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NEXTSTEP 770 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RIS 771 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UNIFY 772 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AUDIT 773 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCBINDER 774 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCSERVER 775 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REMOTE_KIS 776 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KIS 777 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACI 778 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MUMPS 779 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QFT 780 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GACP 781 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PROSPERO 782 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OSU_NMS 783 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SRMP 784 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DN6_NLM_AUD 785 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DN6_SMM_RED 786 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DLS 787 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DLS_MON 788 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMUX 789 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SRC 790 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_RTMP 791 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_NBP 792 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_3 793 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_ECHO 794 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_5 795 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_ZIS 796 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_7 797 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_8 798 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QMTP 799 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_Z39_50 800 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_914C_G 801 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_914CG 802 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ANET 803 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPX 804 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VMPWSCS 805 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SOFTPC 806 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CAILIC 807 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DBASE 808 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPP 809 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UARPS 810 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IMAP3 811 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FLN_SPX 812 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSH_SPX 813 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CDC 814 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MASQDIALER 815 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DIRECT 816 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUR_MEAS 817 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INBUSINESS 818 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LINK 819 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSP3270 820 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUBNTBCST_TFTP 821 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHFHS 822 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SET 823 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ESRO_GEN 824 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPENPORT 825 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSIIOPS 826 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARCISDMS 827 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HDAP 828 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BGMP 829 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_X_BONE_CTL 830 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SST 831 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TD_SERVICE 832 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TD_REPLICA 833 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GIST 834 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PT_TLS 835 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTP_MGMT 836 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PERSONAL_LINK 837 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CABLEPORT_AX 838 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RESCAP 839 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CORERJD 840 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FXP 841 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_K_BLOCK 842 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NOVASTORBAKCUP 843 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUSTTIME 844 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHMDS 845 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASIP_WEBADMIN 846 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VSLMP 847 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAGENTA_LOGIC 848 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPALIS_ROBOT 849 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DPSI 850 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECAUTH 851 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ZANNET 852 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PKIX_TIMESTAMP 853 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PTP_EVENT 854 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PTP_GENERAL 855 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PIP 856 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RTSPS 857 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPKI_RTR 858 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPKI_RTR_TLS 859 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TEXAR 860 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PDAP 861 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PAWSERV 862 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ZSERV 863 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FATSERV 864 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CSI_SGWP 865 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MFTP 866 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MATIP_TYPE_A 867 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MATIP_TYPE_B 868 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHOETTY 869 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DTAG_STE_SB 870 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHOEDAP4 871 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NDSAUTH 872 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BH611 873 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DATEX_ASN 874 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CLOANTO_NET_1 875 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHEVENT 876 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SHRINKWRAP 877 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSRMP 878 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCOI2ODIALOG 879 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SEMANTIX 880 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SRSSEND 881 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSVP_TUNNEL 882 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AURORA_CMGR 883 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DTK 884 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ODMR 885 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MORTGAGEWARE 886 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QBIKGDP 887 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPC2PORTMAP 888 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CODAAUTH2 889 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CLEARCASE 890 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ULISTPROC 891 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LEGENT_1 892 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LEGENT_2 893 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HASSLE 894 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NIP 895 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TNETOS 896 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSETOS 897 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IS99C 898 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IS99S 899 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HP_COLLECTOR 900 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HP_MANAGED_NODE 901 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HP_ALARM_MGR 902 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARNS 903 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IBM_APP 904 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASA 905 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AURP 906 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UNIDATA_LDM 907 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UIS 908 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYNOTICS_RELAY 909 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYNOTICS_BROKER 910 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_META5 911 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EMBL_NDT 912 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCP 913 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETWARE_IP 914 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPTN 915 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_TSAP_C2 916 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OSB_SD 917 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UPS 918 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GENIE 919 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECAP 920 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NCED 921 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NCLD 922 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IMSP 923 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TIMBUKTU 924 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRM_SM 925 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRM_NM 926 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECLADEBUG 927 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RMT 928 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYNOPTICS_TRAP 929 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMSP 930 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INFOSEEK 931 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BNET 932 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SILVERPLATTER 933 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ONMUX 934 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HYPER_G 935 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARIEL1 936 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMPTE 937 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARIEL2 938 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARIEL3 939 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPC_JOB_START 940 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPC_JOB_TRACK 941 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ICAD_EL 942 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMARTSDP 943 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SVRLOC 944 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCS_CMU 945 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCS_AMU 946 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UTMPSD 947 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UTMPCD 948 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IASD 949 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NNSP 950 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MOBILEIP_AGENT 951 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MOBILIP_MN 952 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DNA_CML 953 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMSCM 954 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSFGW 955 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DASP 956 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SGCP 957 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECVMS_SYSMGT 958 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CVC_HOSTD 959 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTPS 960 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNPP 961 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MICROSOFT_DS 962 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DDM_RDB 963 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DDM_DFM 964 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DDM_SSL 965 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AS_SERVERMAP 966 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TSERVER 967 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SFS_SMP_NET 968 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SFS_CONFIG 969 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CREATIVESERVER 970 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CONTENTSERVER 971 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CREATIVEPARTNR 972 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MACON_TCP 973 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MACON_UDP 974 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCOHELP 975 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APPLEQTC 976 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AMPR_RCMD 977 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SKRONK 978 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DATASURFSRV 979 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DATASURFSRVSEC 980 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ALPES 981 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KPASSWD 982 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_URD 983 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IGMPV3LITE 984 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DIGITAL_VRC 985 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MYLEX_MAPD 986 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PHOTURIS 987 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RCP 988 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCX_PROXY 989 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MONDEX 990 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LJK_LOGIN 991 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HYBRID_POP 992 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TN_TL_W1 993 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TN_TL_W2 994 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TCPNETHASPSRV 995 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TN_TL_FD1 996 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SS7NS 997 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SPSC 998 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IAFSERVER 999 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IAFDBASE 1000 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PH 1001 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BGS_NSI 1002 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ULPNET 1003 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INTEGRA_SME 1004 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POWERBURST 1005 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AVIAN 1006 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SAFT 1007 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GSS_HTTP 1008 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NEST_PROTOCOL 1009 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MICOM_PFS 1010 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GO_LOGIN 1011 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TICF_1 1012 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TICF_2 1013 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POV_RAY 1014 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INTECOURIER 1015 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PIM_RP_DISC 1016 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RETROSPECT 1017 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SIAM 1018 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_ILL 1019 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISAKMP 1020 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STMF 1021 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MBAP 1022 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INTRINSA 1023 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CITADEL 1024 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAILBOX_LM 1025 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OHIMSRV 1026 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CRS 1027 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XVTTP 1028 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNARE 1029 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FCP 1030 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PASSGO 1031 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EXEC 1032 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMSAT 1033 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BIFF 1034 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOGIN 1035 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHO 1036 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SHELL 1037 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRINTER 1038 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VIDEOTEX 1039 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TALK 1040 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NTALK 1041 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UTIME 1042 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EFS 1043 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ROUTER 1044 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RIPNG 1045 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ULP 1046 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IBM_DB2 1047 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NCP 1048 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TIMED 1049 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TEMPO 1050 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STX 1051 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CUSTIX 1052 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRC_SERV 1053 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COURIER 1054 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CONFERENCE 1055 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETNEWS 1056 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETWALL 1057 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WINDREAM 1058 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IIOP 1059 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPALIS_RDV 1060 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NMSP 1061 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GDOMAP 1062 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APERTUS_LDP 1063 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUCP 1064 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUCP_RLOGIN 1065 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMMERCE 1066 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KLOGIN 1067 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KSHELL 1068 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APPLEQTCSRVR 1069 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCPV6_CLIENT 1070 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCPV6_SERVER 1071 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AFPOVERTCP 1072 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDFP 1073 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NEW_RWHO 1074 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CYBERCASH 1075 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEVSHR_NTS 1076 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PIRP 1077 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSF 1078 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REMOTEFS 1079 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPENVMS_SYSIPC 1080 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SDNSKMP 1081 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TEEDTAP 1082 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RMONITOR 1083 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MONITOR 1084 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CHSHELL 1085 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NNTPS 1086 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_9PFS 1087 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHOAMI 1088 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STREETTALK 1089 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BANYAN_RPC 1090 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MS_SHUTTLE 1091 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MS_ROME 1092 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_METER 1093 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SONAR 1094 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BANYAN_VIP 1095 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTP_AGENT 1096 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VEMMI 1097 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPCD 1098 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VNAS 1099 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPDD 1100 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECBSRV 1101 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNTP_HEARTBEAT 1102 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BDP 1103 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCC_SECURITY 1104 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PHILIPS_VC 1105 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KEYSERVER 1106 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PASSWORD_CHG 1107 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUBMISSION 1108 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CAL 1109 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EYELINK 1110 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TNS_CML 1111 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTP_ALT 1112 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EUDORA_SET 1113 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTP_RPC_EPMAP 1114 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TPIP 1115 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CAB_PROTOCOL 1116 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMSD 1117 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PTCNAMESERVICE 1118 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_WEBSRVRMG3 1119 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACP 1120 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPCSERVER 1121 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYSLOG_CONN 1122 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XMLRPC_BEEP 1123 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDXP 1124 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TUNNEL 1125 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SOAP_BEEP 1126 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_URM 1127 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NQS 1128 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SIFT_UFT 1129 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPMP_TRAP 1130 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPMP_LOCAL 1131 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPMP_GUI 1132 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HMMP_IND 1133 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HMMP_OP 1134 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SSHELL 1135 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_INETMGR 1136 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_SYSMGR 1137 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_DTMGR 1138 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEI_ICDA 1139 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMPAQ_EVM 1140 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_WEBSRVRMGR 1141 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ESCP_IP 1142 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COLLABORATOR 1143 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OOB_WS_HTTP 1144 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASF_RMCP 1145 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CRYPTOADMIN 1146 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEC_DLM 1147 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASIA 1148 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PASSGO_TIVOLI 1149 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QMQP 1150 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_3COM_AMP3 1151 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RDA 1152 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BMPP 1153 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SERVSTAT 1154 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GINAD 1155 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RLZDBASE 1156 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LDAPS 1157 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LANSERVER 1158 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MCNS_SEC 1159 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSDP 1160 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_SPS 1161 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REPCMD 1162 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ESRO_EMSDP 1163 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SANITY 1164 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DWR 1165 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PSSC 1166 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LDP 1167 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCP_FAILOVER 1168 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RRP 1169 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CADVIEW_3D 1170 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OBEX 1171 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IEEE_MMS 1172 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HELLO_PORT 1173 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REPSCMD 1174 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AODV 1175 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TINC 1176 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SPMP 1177 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RMC 1178 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TENFOLD 1179 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAC_SRVR_ADMIN 1180 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HAP 1181 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PFTP 1182 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PURENOISE 1183 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OOB_WS_HTTPS 1184 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASF_SECURE_RMCP 1185 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUN_DR 1186 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MDQS 1187 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DOOM 1188 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DISCLOSE 1189 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MECOMM 1190 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MEREGISTER 1191 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VACDSM_SWS 1192 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VACDSM_APP 1193 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VPPS_QUA 1194 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CIMPLEX 1195 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACAP 1196 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DCTP 1197 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VPPS_VIA 1198 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VPP 1199 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GGF_NCP 1200 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MRM 1201 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_AAAS 1202 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_AAMS 1203 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XFR 1204 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CORBA_IIOP 1205 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CORBA_IIOP_SSL 1206 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MDC_PORTMAPPER 1207 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HCP_WISMAR 1208 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASIPREGISTRY 1209 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REALM_RUSD 1210 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NMAP 1211 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VATP 1212 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSEXCH_ROUTING 1213 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HYPERWAVE_ISP 1214 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CONNENDP 1215 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HA_CLUSTER 1216 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IEEE_MMS_SSL 1217 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RUSHD 1218 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUIDGEN 1219 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OLSR 1220 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACCESSNETWORK 1221 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EPP 1222 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LMP 1223 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_BEEP 1224 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ELCSD 1225 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AGENTX 1226 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SILC 1227 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BORLAND_DSJ 1228 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_KMSH 1229 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_ASH 1230 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_TDP 1231 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TBRPF 1232 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_XPC 1233 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_XPCS 1234 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_LWZ 1235 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PANA 1236 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETVIEWDM1 1237 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETVIEWDM2 1238 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETVIEWDM3 1239 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETGW 1240 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRCS 1241 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FLEXLM 1242 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FUJITSU_DEV 1243 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RIS_CM 1244 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KERBEROS_ADM 1245 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RFILE 1246 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOADAV 1247 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KERBEROS_IV 1248 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PUMP 1249 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QRH 1250 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RRH 1251 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TELL 1252 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NLOGIN 1253 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CON 1254 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NS 1255 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RXE 1256 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QUOTAD 1257 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CYCLESERV 1258 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OMSERV 1259 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WEBSTER 1260 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PHONEBOOK 1261 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VID 1262 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CADLOCK 1263 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RTIP 1264 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CYCLESERV2 1265 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUBMIT 1266 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NOTIFY 1267 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPASSWD 1268 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACMAINT_DBD 1269 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTOMB 1270 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACMAINT_TRANSD 1271 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WPAGES 1272 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MULTILING_HTTP 1273 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WPGS 1274 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MDBS_DAEMON 1275 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEVICE 1276 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MBAP_S 1277 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FCP_UDP 1278 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ITM_MCELL_S 1279 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PKIX_3_CA_RA 1280 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONF_SSH 1281 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONF_BEEP 1282 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONFSOAPHTTP 1283 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONFSOAPBEEP 1284 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCP_FAILOVER2 1285 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GDOI 1286 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DOMAIN_S 1287 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISCSI 1288 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OWAMP_CONTROL 1289 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TWAMP_CONTROL 1290 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSYNC 1291 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ICLCNET_LOCATE 1292 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ICLCNET_SVINFO 1293 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACCESSBUILDER 1294 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CDDBP 1295 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OMGINITIALREFS 1296 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMPNAMERES 1297 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDEAFARM_DOOR 1298 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDEAFARM_PANIC 1299 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KINK 1300 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XACT_BACKUP 1301 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APEX_MESH 1302 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APEX_EDGE 1303 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTPS_DATA 1304 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTPS 1305 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAS 1306 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TELNETS 1307 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POP3S 1308 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VSINET 1309 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAITRD 1310 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BUSBOY 1311 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PUPARP 1312 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GARCON 1313 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APPLIX 1314 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PUPROUTER 1315 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CADLOCK2 1316 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SURF 1317 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EXP1 1318 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EXP2 1319 // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BLACKJACK 1320 // was generated by MMTCrawler on 8 mar 2016 @luongnv89

#define LAST_IMPLEMENTED_PROTOCOL PROTO_BLACKJACK

#define NB_SUPPORTED_PROTOCOLS (LAST_IMPLEMENTED_PROTOCOL + 1)

//#define PROTO_UNKNOWN_ALIAS "ukn" //Already defined in the core
//#define PROTO_META_ALIAS "META" //Already defined in the core
#define PROTO_163_ALIAS "163"
#define PROTO_360_ALIAS "360"
#define PROTO_302_FOUND_ALIAS "302_found"
#define PROTO_360BUY_ALIAS "360buy"
#define PROTO_56_ALIAS "56"
#define PROTO_8021Q_ALIAS "8021q"
#define PROTO_888_ALIAS "888"
#define PROTO_ABOUT_ALIAS "about"
#define PROTO_ADCASH_ALIAS "adcash"
#define PROTO_ADDTHIS_ALIAS "addthis"
#define PROTO_ADF_ALIAS "adf"
#define PROTO_ADOBE_ALIAS "adobe"
#define PROTO_AFP_ALIAS "afp"
#define PROTO_AH_ALIAS "ah"
#define PROTO_AIM_ALIAS "aim"
#define PROTO_AIMINI_ALIAS "aimini"
#define PROTO_ALIBABA_ALIAS "alibaba"
#define PROTO_ALIPAY_ALIAS "alipay"
#define PROTO_ALLEGRO_ALIAS "allegro"
#define PROTO_AMAZON_ALIAS "amazon"
#define PROTO_AMEBLO_ALIAS "ameblo"
#define PROTO_ANCESTRY_ALIAS "ancestry"
#define PROTO_ANGRYBIRDS_ALIAS "angrybirds"
#define PROTO_ANSWERS_ALIAS "answers"
#define PROTO_AOL_ALIAS "aol"
#define PROTO_APPLE_ALIAS "apple"
#define PROTO_APPLEJUICE_ALIAS "applejuice"
#define PROTO_ARMAGETRON_ALIAS "armagetron"
#define PROTO_ARP_ALIAS "arp"
#define PROTO_ASK_ALIAS "ask"
#define PROTO_AVG_ALIAS "avg"
#define PROTO_AVI_ALIAS "avi"
#define PROTO_AWEBER_ALIAS "aweber"
#define PROTO_AWS_ALIAS "aws"
#define PROTO_BABYLON_ALIAS "babylon"
#define PROTO_BADOO_ALIAS "badoo"
#define PROTO_BAIDU_ALIAS "baidu"
#define PROTO_BANKOFAMERICA_ALIAS "bankofamerica"
#define PROTO_BARNESANDNOBLE_ALIAS "barnesandnoble"
#define PROTO_BATMAN_ALIAS "batman"
#define PROTO_BATTLEFIELD_ALIAS "battlefield"
#define PROTO_BATTLENET_ALIAS "battlenet"
#define PROTO_BBB_ALIAS "bbb"
#define PROTO_BBC_ONLINE_ALIAS "bbc_online"
#define PROTO_BESTBUY_ALIAS "bestbuy"
#define PROTO_BETFAIR_ALIAS "betfair"
#define PROTO_BGP_ALIAS "bgp"
#define PROTO_BIBLEGATEWAY_ALIAS "biblegateway"
#define PROTO_BILD_ALIAS "bild"
#define PROTO_BING_ALIAS "bing"
#define PROTO_BITTORRENT_ALIAS "bittorrent"
#define PROTO_BLEACHERREPORT_ALIAS "bleacherreport"
#define PROTO_BLOGFA_ALIAS "blogfa"
#define PROTO_BLOGGER_ALIAS "blogger"
#define PROTO_BLOGSPOT_ALIAS "blogspot"
#define PROTO_BODYBUILDING_ALIAS "bodybuilding"
#define PROTO_BOOKING_ALIAS "booking"
#define PROTO_CBSSPORTS_ALIAS "cbssports"
#define PROTO_CENT_ALIAS "cent"
#define PROTO_CHANGE_ALIAS "change"
#define PROTO_CHASE_ALIAS "chase"
#define PROTO_CHESS_ALIAS "chess"
#define PROTO_CHINAZ_ALIAS "chinaz"
#define PROTO_CITRIX_ALIAS "citrix"
#define PROTO_CITRIXONLINE_ALIAS "citrixonline"
#define PROTO_CLICKSOR_ALIAS "clicksor"
#define PROTO_CNN_ALIAS "cnn"
#define PROTO_CNZZ_ALIAS "cnzz"
#define PROTO_COMCAST_ALIAS "comcast"
#define PROTO_CONDUIT_ALIAS "conduit"
#define PROTO_COPYSCAPE_ALIAS "copyscape"
#define PROTO_CORREIOS_ALIAS "correios"
#define PROTO_CRAIGSLIST_ALIAS "craigslist"
#define PROTO_CROSSFIRE_ALIAS "crossfire"
#define PROTO_DAILYMAIL_ALIAS "dailymail"
#define PROTO_DAILYMOTION_ALIAS "dailymotion"
#define PROTO_DCERPC_ALIAS "dcerpc"
#define PROTO_DIRECT_DOWNLOAD_LINK_ALIAS "direct_download_link"
#define PROTO_DEVIANTART_ALIAS "deviantart"
#define PROTO_DHCP_ALIAS "dhcp"
#define PROTO_DHCPV6_ALIAS "dhcpv6"
#define PROTO_DIGG_ALIAS "digg"
#define PROTO_DIRECTCONNECT_ALIAS "directconnect"
#define PROTO_DNS_ALIAS "dns"
#define PROTO_DOFUS_ALIAS "dofus"
#define PROTO_DONANIMHABER_ALIAS "donanimhaber"
#define PROTO_DOUBAN_ALIAS "douban"
#define PROTO_DOUBLECLICK_ALIAS "doubleclick"
#define PROTO_DROPBOX_ALIAS "dropbox"
#define PROTO_EBAY_ALIAS "ebay"
#define PROTO_EDONKEY_ALIAS "edonkey"
#define PROTO_EGP_ALIAS "egp"
#define PROTO_EHOW_ALIAS "ehow"
#define PROTO_EKSISOZLUK_ALIAS "eksisozluk"
#define PROTO_ELECTRONICSARTS_ALIAS "electronicsarts"
#define PROTO_ESP_ALIAS "esp"
#define PROTO_ESPN_ALIAS "espn"
#define PROTO_ETHERNET_ALIAS "ethernet"
#define PROTO_ETSY_ALIAS "etsy"
#define PROTO_EUROPA_ALIAS "europa"
#define PROTO_EUROSPORT_ALIAS "eurosport"
#define PROTO_FACEBOOK_ALIAS "facebook"
#define PROTO_FACETIME_ALIAS "facetime"
#define PROTO_FASTTRACK_ALIAS "fasttrack"
#define PROTO_FC2_ALIAS "fc2"
#define PROTO_FEIDIAN_ALIAS "feidian"
#define PROTO_FIESTA_ALIAS "fiesta"
#define PROTO_FILETOPIA_ALIAS "filetopia"
#define PROTO_FIVERR_ALIAS "fiverr"
#define PROTO_FLASH_ALIAS "rtmp"
#define PROTO_FLICKR_ALIAS "flickr"
#define PROTO_FLORENSIA_ALIAS "florensia"
#define PROTO_FOURSQUARE_ALIAS "foursquare"
#define PROTO_FOX_ALIAS "fox"
#define PROTO_FREE_ALIAS "free"
#define PROTO_FTP_ALIAS "ftp"
#define PROTO_GADUGADU_ALIAS "gadugadu"
#define PROTO_GAMEFAQS_ALIAS "gamefaqs"
#define PROTO_GAMESPOT_ALIAS "gamespot"
#define PROTO_GAP_ALIAS "gap"
#define PROTO_GARANTI_ALIAS "garanti"
#define PROTO_GAZETEVATAN_ALIAS "gazetevatan"
#define PROTO_GIGAPETA_ALIAS "gigapeta"
#define PROTO_GITHUB_ALIAS "github"
#define PROTO_GITTIGIDIYOR_ALIAS "gittigidiyor"
#define PROTO_GLOBO_ALIAS "globo"
#define PROTO_GMAIL_ALIAS "gmail"
#define PROTO_GNUTELLA_ALIAS "gnutella"
#define PROTO_GOOGLE_MAPS_ALIAS "google_maps"
#define PROTO_GO_ALIAS "go"
#define PROTO_GODADDY_ALIAS "godaddy"
#define PROTO_GOO_ALIAS "goo"
#define PROTO_GOOGLE_ALIAS "google"
#define PROTO_GOOGLE_USER_CONTENT_ALIAS "google_user_content"
#define PROTO_GOSMS_ALIAS "gosms"
#define PROTO_GRE_ALIAS "gre"
#define PROTO_GROOVESHARK_ALIAS "grooveshark"
#define PROTO_GROUPON_ALIAS "groupon"
#define PROTO_GTALK_ALIAS "gtalk"
#define PROTO_GTP_ALIAS "gtp"
#define PROTO_GTP2_ALIAS "gtp2"
#define PROTO_GUARDIAN_ALIAS "guardian"
#define PROTO_GUILDWARS_ALIAS "guildwars"
#define PROTO_HABERTURK_ALIAS "haberturk"
#define PROTO_HAO123_ALIAS "hao123"
#define PROTO_HEPSIBURADA_ALIAS "hepsiburada"
#define PROTO_HI5_ALIAS "hi5"
#define PROTO_HALFLIFE2_ALIAS "halflife2"
#define PROTO_HOMEDEPOT_ALIAS "homedepot"
#define PROTO_HOOTSUITE_ALIAS "hootsuite"
#define PROTO_HOTMAIL_ALIAS "hotmail"
#define PROTO_HTTP_ALIAS "http"
#define PROTO_HTTP_CONNECT_ALIAS "http_connect"
#define PROTO_HTTP_PROXY_ALIAS "http_proxy"
#define PROTO_HTTP_APPLICATION_ACTIVESYNC_ALIAS "http_activesync"
#define PROTO_HUFFINGTON_POST_ALIAS "huffingtonpost"
#define PROTO_HURRIYET_ALIAS "hurriyet"
#define PROTO_I23V5_ALIAS "i23v5"
#define PROTO_IAX_ALIAS "iax"
#define PROTO_ICECAST_ALIAS "icecast"
#define PROTO_APPLE_ICLOUD_ALIAS "icloud"
#define PROTO_ICMP_ALIAS "icmp"
#define PROTO_ICMPV6_ALIAS "icmpv6"
#define PROTO_IFENG_ALIAS "ifeng"
#define PROTO_IGMP_ALIAS "igmp"
#define PROTO_IGN_ALIAS "ign"
#define PROTO_IKEA_ALIAS "ikea"
#define PROTO_IMAP_ALIAS "imap"
#define PROTO_IMAPS_ALIAS "imaps"
#define PROTO_INTERNET_MOVIE_DATABASE_ALIAS "imdb"
#define PROTO_IMESH_ALIAS "imesh"
#define PROTO_IMESSAGE_ALIAS "imessage"
#define PROTO_IMGUR_ALIAS "imgur"
#define PROTO_INCREDIBAR_ALIAS "incredibar"
#define PROTO_INDIATIMES_ALIAS "indiatimes"
#define PROTO_INSTAGRAM_ALIAS "instagram"
#define PROTO_IP_ALIAS "ip"
#define PROTO_IP_IN_IP_ALIAS "ip_in_ip"
#define PROTO_IPP_ALIAS "ipp"
#define PROTO_IPSEC_ALIAS "ipsec"
#define PROTO_IPV6_ALIAS "ipv6"
#define PROTO_IRC_ALIAS "irc"
#define PROTO_IRS_ALIAS "irs"
#define PROTO_APPLE_ITUNES_ALIAS "apple_itunes"
#define PROTO_UNENCRYPED_JABBER_ALIAS "jabber"
#define PROTO_JAPANPOST_ALIAS "japanpost"
#define PROTO_KAKAO_ALIAS "kakao"
#define PROTO_KAT_ALIAS "kat"
#define PROTO_KAZAA_ALIAS "kazaa"
#define PROTO_KERBEROS_ALIAS "kerberos"
#define PROTO_KING_ALIAS "king"
#define PROTO_KOHLS_ALIAS "kohls"
#define PROTO_KONGREGATE_ALIAS "kongregate"
#define PROTO_KONTIKI_ALIAS "kontiki"
#define PROTO_L2TP_ALIAS "l2tp"
#define PROTO_LASTFM_ALIAS "lastfm"
#define PROTO_LDAP_ALIAS "ldap"
#define PROTO_LEAGUEOFLEGENDS_ALIAS "leagueoflegends"
#define PROTO_LEGACY_ALIAS "legacy"
#define PROTO_LETV_ALIAS "letv"
#define PROTO_LINKEDIN_ALIAS "linkedin"
#define PROTO_LIVE_ALIAS "live"
#define PROTO_LIVEDOOR_ALIAS "livedoor"
#define PROTO_LIVEMAIL_ALIAS "livemail"
#define PROTO_LIVEINTERNET_ALIAS "liveinternet"
#define PROTO_LIVEJASMIN_ALIAS "livejasmin"
#define PROTO_LIVEJOURNAL_ALIAS "livejournal"
#define PROTO_LIVESCORE_ALIAS "livescore"
#define PROTO_LIVINGSOCIAL_ALIAS "livingsocial"
#define PROTO_LOWES_ALIAS "lowes"
#define PROTO_MACYS_ALIAS "macys"
#define PROTO_MAIL_RU_ALIAS "mail_ru"
#define PROTO_MANET_ALIAS "manet"
#define PROTO_MANOLITO_ALIAS "manolito"
#define PROTO_MAPLESTORY_ALIAS "maplestory"
#define PROTO_MATCH_ALIAS "match"
#define PROTO_MDNS_ALIAS "mdns"
#define PROTO_MEDIAFIRE_ALIAS "mediafire"
#define PROTO_MEEBO_ALIAS "meebo"
#define PROTO_MGCP_ALIAS "mgcp"
#define PROTO_MICROSOFT_ALIAS "microsoft"
#define PROTO_MILLIYET_ALIAS "milliyet"
#define PROTO_MINECRAFT_ALIAS "minecraft"
#define PROTO_MINICLIP_ALIAS "miniclip"
#define PROTO_MLBASEBALL_ALIAS "mlbaseball"
#define PROTO_MMO_CHAMPION_ALIAS "mmo_champion"
#define PROTO_MMS_ALIAS "mms"
#define PROTO_MOVE_ALIAS "move"
#define PROTO_MOZILLA_ALIAS "mozilla"
#define PROTO_MPEG_ALIAS "mpeg"
#define PROTO_MSN_ALIAS "msn"
#define PROTO_MSSQL_ALIAS "mssql"
#define PROTO_MULTIPLY_ALIAS "multiply"
#define PROTO_MYNET_ALIAS "mynet"
#define PROTO_MYSPACE_ALIAS "myspace"
#define PROTO_MYSQL_ALIAS "mysql"
#define PROTO_MYWEBSEARCH_ALIAS "mywebsearch"
#define PROTO_NBA_ALIAS "nba"
#define PROTO_NEOBUX_ALIAS "neobux"
#define PROTO_NETBIOS_ALIAS "netbios"
#define PROTO_NETFLIX_ALIAS "netflix"
#define PROTO_NETFLOW_ALIAS "netflow"
#define PROTO_NEWEGG_ALIAS "newegg"
#define PROTO_NEWSMAX_ALIAS "newsmax"
#define PROTO_NFL_ALIAS "nfl"
#define PROTO_NFS_ALIAS "nfs"
#define PROTO_NICOVIDEO_ALIAS "nicovideo"
#define PROTO_NIH_ALIAS "nih"
#define PROTO_NORDSTROM_ALIAS "nordstrom"
#define PROTO_NTP_ALIAS "ntp"
#define PROTO_NYTIMES_ALIAS "nytimes"
#define PROTO_ODNOKLASSNIKI_ALIAS "odnoklassniki"
#define PROTO_OFF_ALIAS "off"
#define PROTO_OGG_ALIAS "ogg"
#define PROTO_ONET_ALIAS "onet"
#define PROTO_OPENFT_ALIAS "openft"
#define PROTO_ORANGEDONKEY_ALIAS "orangedonkey"
#define PROTO_OSCAR_ALIAS "oscar"
#define PROTO_OSPF_ALIAS "ospf"
#define PROTO_OUTBRAIN_ALIAS "outbrain"
#define PROTO_OVERSTOCK_ALIAS "overstock"
#define PROTO_PANDO_ALIAS "pando"
#define PROTO_PAYPAL_ALIAS "paypal"
#define PROTO_PCANYWHERE_ALIAS "pcanywhere"
#define PROTO_PCH_ALIAS "pch"
#define PROTO_PCONLINE_ALIAS "pconline"
#define PROTO_PHOTOBUCKET_ALIAS "photobucket"
#define PROTO_PINTEREST_ALIAS "pinterest"
#define PROTO_PLAYSTATION_ALIAS "playstation"
#define PROTO_POGO_ALIAS "pogo"
#define PROTO_POP_ALIAS "pop"
#define PROTO_POPS_ALIAS "pops"
#define PROTO_POPO_ALIAS "popo"
#define PROTO_PORNHUB_ALIAS "pornhub"
#define PROTO_POSTGRES_ALIAS "postgres"
#define PROTO_PPLIVE_ALIAS "pplive"
#define PROTO_PPP_ALIAS "ppp"
#define PROTO_PPPOE_ALIAS "pppoe"
#define PROTO_PPSTREAM_ALIAS "ppstream"
#define PROTO_PPTP_ALIAS "pptp"
#define PROTO_PREMIERLEAGUE_ALIAS "premierleague"
#define PROTO_QQ_ALIAS "qq"
#define PROTO_QQLIVE_ALIAS "qqlive"
#define PROTO_QUAKE_ALIAS "quake"
#define PROTO_QUICKTIME_ALIAS "quicktime"
#define PROTO_R10_ALIAS "r10"
#define PROTO_RADIUS_ALIAS "radius"
#define PROTO_RAKUTEN_ALIAS "rakuten"
#define PROTO_RDP_ALIAS "rdp"
#define PROTO_REALMEDIA_ALIAS "realmedia"
#define PROTO_REDDIT_ALIAS "reddit"
#define PROTO_REDTUBE_ALIAS "redtube"
#define PROTO_REFERENCE_ALIAS "reference"
#define PROTO_RENREN_ALIAS "renren"
#define PROTO_ROBLOX_ALIAS "roblox"
#define PROTO_ROVIO_ALIAS "rovio"
#define PROTO_RTP_ALIAS "rtp"
#define PROTO_RTSP_ALIAS "rtsp"
#define PROTO_SABAHTR_ALIAS "sabahtr"
#define PROTO_SAHIBINDEN_ALIAS "sahibinden"
#define PROTO_SALESFORCE_ALIAS "salesforce"
#define PROTO_SALON_ALIAS "salon"
#define PROTO_SCTP_ALIAS "sctp"
#define PROTO_SEARCHNU_ALIAS "searchnu"
#define PROTO_SEARCH_RESULTS_ALIAS "search_results"
#define PROTO_SEARS_ALIAS "sears"
#define PROTO_SECONDLIFE_ALIAS "secondlife"
#define PROTO_SECURESERVER_ALIAS "secureserver"
#define PROTO_SFLOW_ALIAS "sflow"
#define PROTO_SHAZAM_ALIAS "shazam"
#define PROTO_SHOUTCAST_ALIAS "shoutcast"
#define PROTO_SINA_ALIAS "sina"
#define PROTO_SIP_ALIAS "sip"
#define PROTO_SITEADVISOR_ALIAS "siteadvisor"
#define PROTO_SKY_ALIAS "sky"
#define PROTO_SKYPE_ALIAS "skype"
#define PROTO_SKYROCK_ALIAS "skyrock"
#define PROTO_SKYSPORTS_ALIAS "skysports"
#define PROTO_SLATE_ALIAS "slate"
#define PROTO_SLIDESHARE_ALIAS "slideshare"
#define PROTO_SMB_ALIAS "smb"
#define PROTO_SMTP_ALIAS "smtp"
#define PROTO_SMTPS_ALIAS "smtps"
#define PROTO_SNMP_ALIAS "snmp"
#define PROTO_SOCRATES_ALIAS "socrates"
#define PROTO_SOFTONIC_ALIAS "softonic"
#define PROTO_SOGOU_ALIAS "sogou"
#define PROTO_SOHU_ALIAS "sohu"
#define PROTO_SOPCAST_ALIAS "sopcast"
#define PROTO_SOSO_ALIAS "soso"
#define PROTO_SOULSEEK_ALIAS "soulseek"
#define PROTO_SOUNDCLOUD_ALIAS "soundcloud"
#define PROTO_SOURGEFORGE_ALIAS "sourgeforge"
#define PROTO_SPIEGEL_ALIAS "spiegel"
#define PROTO_SPORX_ALIAS "sporx"
#define PROTO_SPOTIFY_ALIAS "spotify"
#define PROTO_SQUIDOO_ALIAS "squidoo"
#define PROTO_SSDP_ALIAS "ssdp"
#define PROTO_SSH_ALIAS "ssh"
#define PROTO_SSL_ALIAS "ssl"
#define PROTO_STACK_OVERFLOW_ALIAS "stack_overflow"
#define PROTO_STATCOUNTER_ALIAS "statcounter"
#define PROTO_STEALTHNET_ALIAS "stealthnet"
#define PROTO_STEAM_ALIAS "steam"
#define PROTO_STUMBLEUPON_ALIAS "stumbleupon"
#define PROTO_STUN_ALIAS "stun"
#define PROTO_SULEKHA_ALIAS "sulekha"
#define PROTO_SYSLOG_ALIAS "syslog"
#define PROTO_TAGGED_ALIAS "tagged"
#define PROTO_TAOBAO_ALIAS "taobao"
#define PROTO_TARGET_ALIAS "target"
#define PROTO_TCO_ALIAS "tco"
#define PROTO_TCP_ALIAS "tcp"
#define PROTO_TDS_ALIAS "tds"
#define PROTO_TEAMVIEWER_ALIAS "teamviewer"
#define PROTO_TELNET_ALIAS "telnet"
#define PROTO_TFTP_ALIAS "tftp"
#define PROTO_THEMEFOREST_ALIAS "themeforest"
#define PROTO_THE_PIRATE_BAY_ALIAS "the_pirate_bay"
#define PROTO_THUNDER_ALIAS "thunder"
#define PROTO_TIANYA_ALIAS "tianya"
#define PROTO_TLS_ALIAS "tls"
#define PROTO_TMALL_ALIAS "tmall"
#define PROTO_TORRENTZ_ALIAS "torrentz"
#define PROTO_TRUPHONE_ALIAS "truphone"
#define PROTO_TUBE8_ALIAS "tube8"
#define PROTO_TUDOU_ALIAS "tudou"
#define PROTO_TUENTI_ALIAS "tuenti"
#define PROTO_TUMBLR_ALIAS "tumblr"
#define PROTO_TVANTS_ALIAS "tvants"
#define PROTO_TVUPLAYER_ALIAS "tvuplayer"
#define PROTO_TWITTER_ALIAS "twitter"
#define PROTO_UBI_ALIAS "ubi"
#define PROTO_UCOZ_ALIAS "ucoz"
#define PROTO_UDP_ALIAS "udp"
#define PROTO_UDPLITE_ALIAS "udplite"
#define PROTO_UOL_ALIAS "uol"
#define PROTO_USDEPARTMENTOFSTATE_ALIAS "usdepartmentofstate"
#define PROTO_USENET_ALIAS "usenet"
#define PROTO_USTREAM_ALIAS "ustream"
#define PROTO_HTTP_APPLICATION_VEOHTV_ALIAS "http_application_veohtv"
#define PROTO_VIADEO_ALIAS "viadeo"
#define PROTO_VIBER_ALIAS "viber"
#define PROTO_VIMEO_ALIAS "vimeo"
#define PROTO_VK_ALIAS "vk"
#define PROTO_VKONTAKTE_ALIAS "vkontakte"
#define PROTO_VNC_ALIAS "vnc"
#define PROTO_WALMART_ALIAS "walmart"
#define PROTO_WARRIORFORUM_ALIAS "warriorforum"
#define PROTO_WAYN_ALIAS "wayn"
#define PROTO_WEATHER_ALIAS "weather"
#define PROTO_WEBEX_ALIAS "webex"
#define PROTO_WEEKLYSTANDARD_ALIAS "weeklystandard"
#define PROTO_WEIBO_ALIAS "weibo"
#define PROTO_WELLSFARGO_ALIAS "wellsfargo"
#define PROTO_WHATSAPP_ALIAS "whatsapp"
#define PROTO_WIGETMEDIA_ALIAS "wigetmedia"
#define PROTO_WIKIA_ALIAS "wikia"
#define PROTO_WIKIMEDIA_ALIAS "wikimedia"
#define PROTO_WIKIPEDIA_ALIAS "wikipedia"
#define PROTO_WILLIAMHILL_ALIAS "williamhill"
#define PROTO_WINDOWSLIVE_ALIAS "windowslive"
#define PROTO_WINDOWSMEDIA_ALIAS "windowsmedia"
#define PROTO_WINMX_ALIAS "winmx"
#define PROTO_WINUPDATE_ALIAS "winupdate"
#define PROTO_WORLD_OF_KUNG_FU_ALIAS "world_of_kung_fu"
#define PROTO_WORDPRESS_ORG_ALIAS "wordpress_org"
#define PROTO_WARCRAFT3_ALIAS "warcraft3"
#define PROTO_WORLDOFWARCRAFT_ALIAS "worldofwarcraft"
#define PROTO_WOWHEAD_ALIAS "wowhead"
#define PROTO_WWE_ALIAS "wwe"
#define PROTO_XBOX_ALIAS "xbox"
#define PROTO_XDMCP_ALIAS "xdmcp"
#define PROTO_XHAMSTER_ALIAS "xhamster"
#define PROTO_XING_ALIAS "xing"
#define PROTO_XINHUANET_ALIAS "xinhuanet"
#define PROTO_XNXX_ALIAS "xnxx"
#define PROTO_XVIDEOS_ALIAS "xvideos"
#define PROTO_YAHOO_ALIAS "yahoo"
#define PROTO_YAHOOGAMES_ALIAS "yahoogames"
#define PROTO_YAHOOMAIL_ALIAS "yahoomail"
#define PROTO_YANDEX_ALIAS "yandex"
#define PROTO_YELP_ALIAS "yelp"
#define PROTO_YOUKU_ALIAS "youku"
#define PROTO_YOUPORN_ALIAS "youporn"
#define PROTO_YOUTUBE_ALIAS "youtube"
#define PROTO_ZAPPOS_ALIAS "zappos"
#define PROTO_ZATTOO_ALIAS "zattoo"
#define PROTO_ZEDO_ALIAS "zedo"
#define PROTO_ZOL_ALIAS "zol"
#define PROTO_ZYNGA_ALIAS "zynga"
#define PROTO_3PC_ALIAS "3pc"
#define PROTO_ANY_0HOP_ALIAS "any_0hop"
#define PROTO_ANY_DFS_ALIAS "any_dfs"
#define PROTO_ANY_HIP_ALIAS "any_hip"
#define PROTO_ANY_LOCAL_ALIAS "any_local"
#define PROTO_ANY_PES_ALIAS "any_pes"
#define PROTO_ARGUS_ALIAS "argus"
#define PROTO_ARIS_ALIAS "aris"
#define PROTO_AX_25_ALIAS "ax_25"
#define PROTO_BBN_RCC_MON_ALIAS "bbn_rcc_mon"
#define PROTO_BNA_ALIAS "bna"
#define PROTO_BR_SAT_MON_ALIAS "br_sat_mon"
#define PROTO_CBT_ALIAS "cbt"
#define PROTO_CFTP_ALIAS "cftp"
#define PROTO_CHAOS_ALIAS "chaos"
#define PROTO_COMPAQ_PEER_ALIAS "compaq_peer"
#define PROTO_CPHB_ALIAS "cphb"
#define PROTO_CPNX_ALIAS "cpnx"
#define PROTO_CRTP_ALIAS "crtp"
#define PROTO_CRUDP_ALIAS "crudp"
#define PROTO_DCCP_ALIAS "dccp"
#define PROTO_DCN_MEAS_ALIAS "dcn_meas"
#define PROTO_DDP_ALIAS "ddp"
#define PROTO_DDX_ALIAS "ddx"
#define PROTO_DGP_ALIAS "dgp"
#define PROTO_EIGRP_ALIAS "eigrp"
#define PROTO_EMCON_ALIAS "emcon"
#define PROTO_ENCAP_ALIAS "encap"
#define PROTO_ETHERIP_ALIAS "etherip"
#define PROTO_FC_ALIAS "fc"
#define PROTO_FIRE_ALIAS "fire"
#define PROTO_GGP_ALIAS "ggp"
#define PROTO_GMTP_ALIAS "gmtp"
#define PROTO_HIP_ALIAS "hip"
#define PROTO_HMP_ALIAS "hmp"
#define PROTO_I_NLSP_ALIAS "i_nlsp"
#define PROTO_IATP_ALIAS "iatp"
#define PROTO_IDPR_ALIAS "idpr"
#define PROTO_IDPR_CMTP_ALIAS "idpr_cmtp"
#define PROTO_IDRP_ALIAS "idrp"
#define PROTO_IFMP_ALIAS "ifmp"
#define PROTO_IGP_ALIAS "igp"
#define PROTO_IL_ALIAS "il"
#define PROTO_IPCOMP_ALIAS "ipcomp"
#define PROTO_IPCV_ALIAS "ipcv"
#define PROTO_IPLT_ALIAS "iplt"
#define PROTO_IPPC_ALIAS "ippc"
#define PROTO_IPTM_ALIAS "iptm"
#define PROTO_IPX_IN_IP_ALIAS "ipx_in_ip"
#define PROTO_IRTP_ALIAS "irtp"
#define PROTO_IS_IS_ALIAS "is_is"
#define PROTO_ISO_IP_ALIAS "iso_ip"
#define PROTO_ISO_TP4_ALIAS "iso_tp4"
#define PROTO_KRYPTOLAN_ALIAS "kryptolan"
#define PROTO_LARP_ALIAS "larp"
#define PROTO_LEAF_1_ALIAS "leaf_1"
#define PROTO_LEAF_2_ALIAS "leaf_2"
#define PROTO_MERIT_INP_ALIAS "merit_inp"
#define PROTO_MFE_NSP_ALIAS "mfe_nsp"
#define PROTO_MHRP_ALIAS "mhrp"
#define PROTO_MICP_ALIAS "micp"
#define PROTO_MOBILE_ALIAS "mobile"
#define PROTO_MOBILITY_HEADER_ALIAS "mobility_header"
#define PROTO_MPLS_IN_IP_ALIAS "mpls_in_ip"
#define PROTO_MTP_ALIAS "mtp"
#define PROTO_MUX_ALIAS "mux"
#define PROTO_NARP_ALIAS "narp"
#define PROTO_NETBLT_ALIAS "netblt"
#define PROTO_NSFNET_IGP_ALIAS "nsfnet_igp"
#define PROTO_NVP_II_ALIAS "nvp_ii"
#define PROTO_PGM_ALIAS "pgm"
#define PROTO_PIM_ALIAS "pim"
#define PROTO_PIPE_ALIAS "pipe"
#define PROTO_PNNI_ALIAS "pnni"
#define PROTO_PRM_ALIAS "prm"
#define PROTO_PTP_ALIAS "ptp"
#define PROTO_PUP_ALIAS "pup"
#define PROTO_PVP_ALIAS "pvp"
#define PROTO_QNX_ALIAS "qnx"
#define PROTO_RSVP_ALIAS "rsvp"
#define PROTO_RSVP_E2E_IGNORE_ALIAS "rsvp_e2e_ignore"
#define PROTO_RVD_ALIAS "rvd"
#define PROTO_SAT_EXPAK_ALIAS "sat_expak"
#define PROTO_SAT_MON_ALIAS "sat_mon"
#define PROTO_SCC_SP_ALIAS "scc_sp"
#define PROTO_SCPS_ALIAS "scps"
#define PROTO_SDRP_ALIAS "sdrp"
#define PROTO_SECURE_VMTP_ALIAS "secure_vmtp"
#define PROTO_SHIM6_ALIAS "shim6"
#define PROTO_SKIP_ALIAS "skip"
#define PROTO_SM_ALIAS "sm"
#define PROTO_SMP_ALIAS "smp"
#define PROTO_SNP_ALIAS "snp"
#define PROTO_SPRITE_RPC_ALIAS "sprite_rpc"
#define PROTO_SPS_ALIAS "sps"
#define PROTO_SRP_ALIAS "srp"
#define PROTO_SSCOPMCE_ALIAS "sscopmce"
#define PROTO_ST_ALIAS "st"
#define PROTO_STP_ALIAS "stp"
#define PROTO_SUN_ND_ALIAS "sun_nd"
#define PROTO_SWIPE_ALIAS "swipe"
#define PROTO_TCF_ALIAS "tcf"
#define PROTO_TLSP_ALIAS "tlsp"
#define PROTO_TP_PP_ALIAS "tp_pp"
#define PROTO_TRUNK_1_ALIAS "trunk_1"
#define PROTO_TRUNK_2_ALIAS "trunk_2"
#define PROTO_UTI_ALIAS "uti"
#define PROTO_VINES_ALIAS "vines"
#define PROTO_VISA_ALIAS "visa"
#define PROTO_VMTP_ALIAS "vmtp"
#define PROTO_VRRP_ALIAS "vrrp"
#define PROTO_WB_EXPAK_ALIAS "wb_expak"
#define PROTO_WB_MON_ALIAS "wb_mon"
#define PROTO_WSN_ALIAS "wsn"
#define PROTO_XNET_ALIAS "xnet"
#define PROTO_XNS_IDP_ALIAS "xns_idp"
#define PROTO_XTP_ALIAS "xtp"
#define PROTO_BUZZNET_ALIAS "buzznet"
#define PROTO_COMEDY_ALIAS "comedy"
#define PROTO_RAMBLER_ALIAS "rambler"
#define PROTO_SMUGMUG_ALIAS "smugmug"
#define PROTO_ARCHIEVE_ALIAS "archieve"
#define PROTO_CITYNEWS_ALIAS "citynews"
#define PROTO_SCIENCESTAGE_ALIAS "sciencestage"
#define PROTO_ONEWORLD_ALIAS "oneworld"
#define PROTO_DISQUS_ALIAS "disqus"
#define PROTO_BLOGCU_ALIAS "blogcu"
#define PROTO_EKOLEY_ALIAS "ekoley"
#define PROTO_500PX_ALIAS "500px"
#define PROTO_FOTKI_ALIAS "fotki"
#define PROTO_FOTOLOG_ALIAS "fotolog"
#define PROTO_JALBUM_ALIAS "jalbum"
#define PROTO_LOCKERZ_ALIAS "lockerz"
#define PROTO_PANORAMIO_ALIAS "panoramio"
#define PROTO_SNAPFISH_ALIAS "snapfish"
#define PROTO_WEBSHOTS_ALIAS "webshots"
#define PROTO_MEGA_ALIAS "mega"
#define PROTO_VIDOOSH_ALIAS "vidoosh"
#define PROTO_AFREECA_ALIAS "afreeca"
#define PROTO_WILDSCREEN_ALIAS "wildscreen"
#define PROTO_BLOGTV_ALIAS "blogtv"
#define PROTO_HULU_ALIAS "hulu"
#define PROTO_MEVIO_ALIAS "mevio"
#define PROTO_LIVESTREAM_ALIAS "livestream"
#define PROTO_LIVELEAK_ALIAS "liveleak"
#define PROTO_DEEZER_ALIAS "deezer"
#define PROTO_BLIPTV_ALIAS "bliptv"
#define PROTO_BREAK_ALIAS "break"
#define PROTO_CITYTV_ALIAS "citytv"
#define PROTO_COMEDYCENTRAL_ALIAS "comedycentral"
#define PROTO_ENGAGEMEDIA_ALIAS "engagemedia"
#define PROTO_SCREENJUNKIES_ALIAS "screenjunkies"
#define PROTO_RUTUBE_ALIAS "rutube"
#define PROTO_SEVENLOAD_ALIAS "sevenload"
#define PROTO_MUBI_ALIAS "mubi"
#define PROTO_IZLESENE_ALIAS "izlesene"
#define PROTO_VIDEO_HOSTING_ALIAS "video_hosting"
#define PROTO_BOX_ALIAS "box"
#define PROTO_SKYDRIVE_ALIAS "skydrive"
#define PROTO_7DIGITAL_ALIAS "7digital"
#define PROTO_CLOUDFRONT_ALIAS "cloudfront"
#define PROTO_TANGO_ALIAS "tango"
#define PROTO_WECHAT_ALIAS "wechat"
#define PROTO_LINE_ALIAS "line"
#define PROTO_BLOOMBERG_ALIAS "bloomberg"
#define PROTO_MSCDN_ALIAS "mscdn"
#define PROTO_AKAMAI_ALIAS "akamai"
#define PROTO_YAHOOMSG_ALIAS "yahoomsg"
#define PROTO_BITGRAVITY_ALIAS "bitgravity"
#define PROTO_CACHEFLY_ALIAS "cachefly"
#define PROTO_CDN77_ALIAS "cdn77"
#define PROTO_CDNETWORKS_ALIAS "cdnetworks"
#define PROTO_CHINACACHE_ALIAS "chinacache"
#define PROTO_COTENDO_ALIAS "cotendo"
#define PROTO_EDGECAST_ALIAS "edgecast"
#define PROTO_FASTLY_ALIAS "fastly"
#define PROTO_HIGHWINDS_ALIAS "highwinds"
#define PROTO_INTERNAP_ALIAS "internap"
#define PROTO_LEVEL3_ALIAS "level3"
#define PROTO_LIMELIGHT_ALIAS "limelight"
#define PROTO_MAXCDN_ALIAS "maxcdn"
#define PROTO_NETDNA_ALIAS "netdna"
#define PROTO_VOXEL_ALIAS "voxel"
#define PROTO_RACKSPACE_ALIAS "rackspace"
#define PROTO_GAMEFORGE_ALIAS "gameforge"
#define PROTO_METIN2_ALIAS "metin2"
#define PROTO_OGAME_ALIAS "ogame"
#define PROTO_BATTLEKNIGHT_ALIAS "battleknight"
#define PROTO_4STORY_ALIAS "4story"
#define PROTO_FBMSG_ALIAS "fbmsg"
#define PROTO_GCM_ALIAS "gcm"
#define PROTO_SLL_ALIAS "sll"
#define PROTO_NDN_ALIAS "ndn"
#define PROTO_TCPMUX_ALIAS "tcpmux" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMPRESSNET_ALIAS "compressnet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RJE_ALIAS "rje" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ECHO_ALIAS "echo" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DISCARD_ALIAS "discard" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYSTAT_ALIAS "systat" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DAYTIME_ALIAS "daytime" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QOTD_ALIAS "qotd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSP_ALIAS "msp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CHARGEN_ALIAS "chargen" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTP_DATA_ALIAS "ftp_data" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSW_FE_ALIAS "nsw_fe" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSG_ICP_ALIAS "msg_icp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSG_AUTH_ALIAS "msg_auth" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSP_ALIAS "dsp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TIME_ALIAS "time" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RAP_ALIAS "rap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RLP_ALIAS "rlp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GRAPHICS_ALIAS "graphics" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAME_ALIAS "name" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAMESERVER_ALIAS "nameserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NICNAME_ALIAS "nicname" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPM_FLAGS_ALIAS "mpm_flags" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPM_ALIAS "mpm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPM_SND_ALIAS "mpm_snd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NI_FTP_ALIAS "ni_ftp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AUDITD_ALIAS "auditd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TACACS_ALIAS "tacacs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RE_MAIL_CK_ALIAS "re_mail_ck" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_TIME_ALIAS "xns_time" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DOMAIN_ALIAS "domain" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_CH_ALIAS "xns_ch" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISI_GL_ALIAS "isi_gl" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_AUTH_ALIAS "xns_auth" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_MAIL_ALIAS "xns_mail" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NI_MAIL_ALIAS "ni_mail" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACAS_ALIAS "acas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHOISPP_ALIAS "whoispp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHOIS___ALIAS "whois__" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COVIA_ALIAS "covia" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TACACS_DS_ALIAS "tacacs_ds" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQL_NET_ALIAS "sql_net" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQLNET_ALIAS "sqlnet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BOOTPS_ALIAS "bootps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BOOTPC_ALIAS "bootpc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GOPHER_ALIAS "gopher" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_1_ALIAS "netrjs_1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_2_ALIAS "netrjs_2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_3_ALIAS "netrjs_3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRJS_4_ALIAS "netrjs_4" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEOS_ALIAS "deos" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VETTCP_ALIAS "vettcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FINGER_ALIAS "finger" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WWW_ALIAS "www" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WWW_HTTP_ALIAS "www_http" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XFER_ALIAS "xfer" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MIT_ML_DEV_ALIAS "mit_ml_dev" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CTF_ALIAS "ctf" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MFCOBOL_ALIAS "mfcobol" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SU_MIT_TG_ALIAS "su_mit_tg" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PORT_ALIAS "port" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DNSIX_ALIAS "dnsix" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MIT_DOV_ALIAS "mit_dov" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPP_ALIAS "npp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DCP_ALIAS "dcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OBJCALL_ALIAS "objcall" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUPDUP_ALIAS "supdup" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DIXIE_ALIAS "dixie" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SWIFT_RVF_ALIAS "swift_rvf" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TACNEWS_ALIAS "tacnews" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_METAGRAM_ALIAS "metagram" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HOSTNAME_ALIAS "hostname" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_TSAP_ALIAS "iso_tsap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GPPITNP_ALIAS "gppitnp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACR_NEMA_ALIAS "acr_nema" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CSO_ALIAS "cso" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CSNET_NS_ALIAS "csnet_ns" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_3COM_TSMUX_ALIAS "3com_tsmux" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RTELNET_ALIAS "rtelnet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNAGAS_ALIAS "snagas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POP2_ALIAS "pop2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POP3_ALIAS "pop3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUNRPC_ALIAS "sunrpc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MCIDAS_ALIAS "mcidas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDENT_ALIAS "ident" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AUTH_ALIAS "auth" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SFTP_ALIAS "sftp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ANSANOTIFY_ALIAS "ansanotify" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUCP_PATH_ALIAS "uucp_path" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQLSERV_ALIAS "sqlserv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NNTP_ALIAS "nntp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CFDPTKT_ALIAS "cfdptkt" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ERPC_ALIAS "erpc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMAKYNET_ALIAS "smakynet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ANSATRADER_ALIAS "ansatrader" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOCUS_MAP_ALIAS "locus_map" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NXEDIT_ALIAS "nxedit" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOCUS_CON_ALIAS "locus_con" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GSS_XLICEN_ALIAS "gss_xlicen" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PWDGEN_ALIAS "pwdgen" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_FNA_ALIAS "cisco_fna" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_TNA_ALIAS "cisco_tna" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_SYS_ALIAS "cisco_sys" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STATSRV_ALIAS "statsrv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INGRES_NET_ALIAS "ingres_net" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EPMAP_ALIAS "epmap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PROFILE_ALIAS "profile" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETBIOS_NS_ALIAS "netbios_ns" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETBIOS_DGM_ALIAS "netbios_dgm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETBIOS_SSN_ALIAS "netbios_ssn" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EMFIS_DATA_ALIAS "emfis_data" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EMFIS_CNTL_ALIAS "emfis_cntl" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BL_IDM_ALIAS "bl_idm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UMA_ALIAS "uma" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UAAC_ALIAS "uaac" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_TP0_ALIAS "iso_tp0" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_JARGON_ALIAS "jargon" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AED_512_ALIAS "aed_512" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HEMS_ALIAS "hems" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BFTP_ALIAS "bftp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SGMP_ALIAS "sgmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETSC_PROD_ALIAS "netsc_prod" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETSC_DEV_ALIAS "netsc_dev" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SQLSRV_ALIAS "sqlsrv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KNET_CMP_ALIAS "knet_cmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PCMAIL_SRV_ALIAS "pcmail_srv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSS_ROUTING_ALIAS "nss_routing" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SGMP_TRAPS_ALIAS "sgmp_traps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNMPTRAP_ALIAS "snmptrap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CMIP_MAN_ALIAS "cmip_man" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CMIP_AGENT_ALIAS "cmip_agent" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XNS_COURIER_ALIAS "xns_courier" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_S_NET_ALIAS "s_net" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAMP_ALIAS "namp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSVD_ALIAS "rsvd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SEND_ALIAS "send" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRINT_SRV_ALIAS "print_srv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MULTIPLEX_ALIAS "multiplex" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CL_1_ALIAS "cl_1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CL1_ALIAS "cl1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XYPLEX_MUX_ALIAS "xyplex_mux" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAILQ_ALIAS "mailq" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VMNET_ALIAS "vmnet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GENRAD_MUX_ALIAS "genrad_mux" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NEXTSTEP_ALIAS "nextstep" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RIS_ALIAS "ris" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UNIFY_ALIAS "unify" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AUDIT_ALIAS "audit" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCBINDER_ALIAS "ocbinder" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCSERVER_ALIAS "ocserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REMOTE_KIS_ALIAS "remote_kis" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KIS_ALIAS "kis" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACI_ALIAS "aci" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MUMPS_ALIAS "mumps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QFT_ALIAS "qft" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GACP_ALIAS "gacp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PROSPERO_ALIAS "prospero" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OSU_NMS_ALIAS "osu_nms" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SRMP_ALIAS "srmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DN6_NLM_AUD_ALIAS "dn6_nlm_aud" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DN6_SMM_RED_ALIAS "dn6_smm_red" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DLS_ALIAS "dls" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DLS_MON_ALIAS "dls_mon" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMUX_ALIAS "smux" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SRC_ALIAS "src" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_RTMP_ALIAS "at_rtmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_NBP_ALIAS "at_nbp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_3_ALIAS "at_3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_ECHO_ALIAS "at_echo" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_5_ALIAS "at_5" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_ZIS_ALIAS "at_zis" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_7_ALIAS "at_7" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AT_8_ALIAS "at_8" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QMTP_ALIAS "qmtp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_Z39_50_ALIAS "z39_50" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_914C_G_ALIAS "914c_g" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_914CG_ALIAS "914cg" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ANET_ALIAS "anet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPX_ALIAS "ipx" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VMPWSCS_ALIAS "vmpwscs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SOFTPC_ALIAS "softpc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CAILIC_ALIAS "cailic" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DBASE_ALIAS "dbase" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPP_ALIAS "mpp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UARPS_ALIAS "uarps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IMAP3_ALIAS "imap3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FLN_SPX_ALIAS "fln_spx" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSH_SPX_ALIAS "rsh_spx" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CDC_ALIAS "cdc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MASQDIALER_ALIAS "masqdialer" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DIRECT_ALIAS "direct" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUR_MEAS_ALIAS "sur_meas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INBUSINESS_ALIAS "inbusiness" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LINK_ALIAS "link" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSP3270_ALIAS "dsp3270" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUBNTBCST_TFTP_ALIAS "subntbcst_tftp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHFHS_ALIAS "bhfhs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SET_ALIAS "set" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ESRO_GEN_ALIAS "esro_gen" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPENPORT_ALIAS "openport" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSIIOPS_ALIAS "nsiiops" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARCISDMS_ALIAS "arcisdms" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HDAP_ALIAS "hdap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BGMP_ALIAS "bgmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_X_BONE_CTL_ALIAS "x_bone_ctl" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SST_ALIAS "sst" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TD_SERVICE_ALIAS "td_service" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TD_REPLICA_ALIAS "td_replica" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GIST_ALIAS "gist" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PT_TLS_ALIAS "pt_tls" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTP_MGMT_ALIAS "http_mgmt" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PERSONAL_LINK_ALIAS "personal_link" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CABLEPORT_AX_ALIAS "cableport_ax" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RESCAP_ALIAS "rescap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CORERJD_ALIAS "corerjd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FXP_ALIAS "fxp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_K_BLOCK_ALIAS "k_block" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NOVASTORBAKCUP_ALIAS "novastorbakcup" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUSTTIME_ALIAS "entrusttime" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHMDS_ALIAS "bhmds" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASIP_WEBADMIN_ALIAS "asip_webadmin" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VSLMP_ALIAS "vslmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAGENTA_LOGIC_ALIAS "magenta_logic" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPALIS_ROBOT_ALIAS "opalis_robot" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DPSI_ALIAS "dpsi" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECAUTH_ALIAS "decauth" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ZANNET_ALIAS "zannet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PKIX_TIMESTAMP_ALIAS "pkix_timestamp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PTP_EVENT_ALIAS "ptp_event" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PTP_GENERAL_ALIAS "ptp_general" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PIP_ALIAS "pip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RTSPS_ALIAS "rtsps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPKI_RTR_ALIAS "rpki_rtr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPKI_RTR_TLS_ALIAS "rpki_rtr_tls" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TEXAR_ALIAS "texar" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PDAP_ALIAS "pdap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PAWSERV_ALIAS "pawserv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ZSERV_ALIAS "zserv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FATSERV_ALIAS "fatserv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CSI_SGWP_ALIAS "csi_sgwp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MFTP_ALIAS "mftp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MATIP_TYPE_A_ALIAS "matip_type_a" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MATIP_TYPE_B_ALIAS "matip_type_b" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHOETTY_ALIAS "bhoetty" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DTAG_STE_SB_ALIAS "dtag_ste_sb" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHOEDAP4_ALIAS "bhoedap4" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NDSAUTH_ALIAS "ndsauth" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BH611_ALIAS "bh611" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DATEX_ASN_ALIAS "datex_asn" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CLOANTO_NET_1_ALIAS "cloanto_net_1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BHEVENT_ALIAS "bhevent" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SHRINKWRAP_ALIAS "shrinkwrap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NSRMP_ALIAS "nsrmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCOI2ODIALOG_ALIAS "scoi2odialog" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SEMANTIX_ALIAS "semantix" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SRSSEND_ALIAS "srssend" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSVP_TUNNEL_ALIAS "rsvp_tunnel" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AURORA_CMGR_ALIAS "aurora_cmgr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DTK_ALIAS "dtk" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ODMR_ALIAS "odmr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MORTGAGEWARE_ALIAS "mortgageware" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QBIKGDP_ALIAS "qbikgdp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPC2PORTMAP_ALIAS "rpc2portmap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CODAAUTH2_ALIAS "codaauth2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CLEARCASE_ALIAS "clearcase" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ULISTPROC_ALIAS "ulistproc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LEGENT_1_ALIAS "legent_1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LEGENT_2_ALIAS "legent_2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HASSLE_ALIAS "hassle" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NIP_ALIAS "nip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TNETOS_ALIAS "tnetos" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSETOS_ALIAS "dsetos" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IS99C_ALIAS "is99c" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IS99S_ALIAS "is99s" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HP_COLLECTOR_ALIAS "hp_collector" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HP_MANAGED_NODE_ALIAS "hp_managed_node" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HP_ALARM_MGR_ALIAS "hp_alarm_mgr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARNS_ALIAS "arns" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IBM_APP_ALIAS "ibm_app" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASA_ALIAS "asa" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AURP_ALIAS "aurp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UNIDATA_LDM_ALIAS "unidata_ldm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UIS_ALIAS "uis" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYNOTICS_RELAY_ALIAS "synotics_relay" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYNOTICS_BROKER_ALIAS "synotics_broker" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_META5_ALIAS "meta5" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EMBL_NDT_ALIAS "embl_ndt" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCP_ALIAS "netcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETWARE_IP_ALIAS "netware_ip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MPTN_ALIAS "mptn" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_TSAP_C2_ALIAS "iso_tsap_c2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OSB_SD_ALIAS "osb_sd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UPS_ALIAS "ups" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GENIE_ALIAS "genie" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECAP_ALIAS "decap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NCED_ALIAS "nced" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NCLD_ALIAS "ncld" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IMSP_ALIAS "imsp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TIMBUKTU_ALIAS "timbuktu" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRM_SM_ALIAS "prm_sm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRM_NM_ALIAS "prm_nm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECLADEBUG_ALIAS "decladebug" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RMT_ALIAS "rmt" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYNOPTICS_TRAP_ALIAS "synoptics_trap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMSP_ALIAS "smsp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INFOSEEK_ALIAS "infoseek" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BNET_ALIAS "bnet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SILVERPLATTER_ALIAS "silverplatter" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ONMUX_ALIAS "onmux" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HYPER_G_ALIAS "hyper_g" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARIEL1_ALIAS "ariel1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMPTE_ALIAS "smpte" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARIEL2_ALIAS "ariel2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ARIEL3_ALIAS "ariel3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPC_JOB_START_ALIAS "opc_job_start" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPC_JOB_TRACK_ALIAS "opc_job_track" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ICAD_EL_ALIAS "icad_el" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMARTSDP_ALIAS "smartsdp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SVRLOC_ALIAS "svrloc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCS_CMU_ALIAS "ocs_cmu" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OCS_AMU_ALIAS "ocs_amu" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UTMPSD_ALIAS "utmpsd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UTMPCD_ALIAS "utmpcd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IASD_ALIAS "iasd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NNSP_ALIAS "nnsp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MOBILEIP_AGENT_ALIAS "mobileip_agent" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MOBILIP_MN_ALIAS "mobilip_mn" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DNA_CML_ALIAS "dna_cml" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMSCM_ALIAS "comscm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSFGW_ALIAS "dsfgw" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DASP_ALIAS "dasp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SGCP_ALIAS "sgcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECVMS_SYSMGT_ALIAS "decvms_sysmgt" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CVC_HOSTD_ALIAS "cvc_hostd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTPS_ALIAS "https" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNPP_ALIAS "snpp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MICROSOFT_DS_ALIAS "microsoft_ds" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DDM_RDB_ALIAS "ddm_rdb" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DDM_DFM_ALIAS "ddm_dfm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DDM_SSL_ALIAS "ddm_ssl" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AS_SERVERMAP_ALIAS "as_servermap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TSERVER_ALIAS "tserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SFS_SMP_NET_ALIAS "sfs_smp_net" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SFS_CONFIG_ALIAS "sfs_config" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CREATIVESERVER_ALIAS "creativeserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CONTENTSERVER_ALIAS "contentserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CREATIVEPARTNR_ALIAS "creativepartnr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MACON_TCP_ALIAS "macon_tcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MACON_UDP_ALIAS "macon_udp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCOHELP_ALIAS "scohelp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APPLEQTC_ALIAS "appleqtc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AMPR_RCMD_ALIAS "ampr_rcmd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SKRONK_ALIAS "skronk" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DATASURFSRV_ALIAS "datasurfsrv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DATASURFSRVSEC_ALIAS "datasurfsrvsec" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ALPES_ALIAS "alpes" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KPASSWD_ALIAS "kpasswd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_URD_ALIAS "urd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IGMPV3LITE_ALIAS "igmpv3lite" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DIGITAL_VRC_ALIAS "digital_vrc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MYLEX_MAPD_ALIAS "mylex_mapd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PHOTURIS_ALIAS "photuris" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RCP_ALIAS "rcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCX_PROXY_ALIAS "scx_proxy" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MONDEX_ALIAS "mondex" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LJK_LOGIN_ALIAS "ljk_login" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HYBRID_POP_ALIAS "hybrid_pop" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TN_TL_W1_ALIAS "tn_tl_w1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TN_TL_W2_ALIAS "tn_tl_w2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TCPNETHASPSRV_ALIAS "tcpnethaspsrv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TN_TL_FD1_ALIAS "tn_tl_fd1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SS7NS_ALIAS "ss7ns" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SPSC_ALIAS "spsc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IAFSERVER_ALIAS "iafserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IAFDBASE_ALIAS "iafdbase" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PH_ALIAS "ph" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BGS_NSI_ALIAS "bgs_nsi" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ULPNET_ALIAS "ulpnet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INTEGRA_SME_ALIAS "integra_sme" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POWERBURST_ALIAS "powerburst" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AVIAN_ALIAS "avian" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SAFT_ALIAS "saft" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GSS_HTTP_ALIAS "gss_http" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NEST_PROTOCOL_ALIAS "nest_protocol" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MICOM_PFS_ALIAS "micom_pfs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GO_LOGIN_ALIAS "go_login" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TICF_1_ALIAS "ticf_1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TICF_2_ALIAS "ticf_2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POV_RAY_ALIAS "pov_ray" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INTECOURIER_ALIAS "intecourier" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PIM_RP_DISC_ALIAS "pim_rp_disc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RETROSPECT_ALIAS "retrospect" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SIAM_ALIAS "siam" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISO_ILL_ALIAS "iso_ill" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISAKMP_ALIAS "isakmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STMF_ALIAS "stmf" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MBAP_ALIAS "mbap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_INTRINSA_ALIAS "intrinsa" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CITADEL_ALIAS "citadel" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAILBOX_LM_ALIAS "mailbox_lm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OHIMSRV_ALIAS "ohimsrv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CRS_ALIAS "crs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XVTTP_ALIAS "xvttp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNARE_ALIAS "snare" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FCP_ALIAS "fcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PASSGO_ALIAS "passgo" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EXEC_ALIAS "exec" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMSAT_ALIAS "comsat" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BIFF_ALIAS "biff" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOGIN_ALIAS "login" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHO_ALIAS "who" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SHELL_ALIAS "shell" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PRINTER_ALIAS "printer" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VIDEOTEX_ALIAS "videotex" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TALK_ALIAS "talk" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NTALK_ALIAS "ntalk" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UTIME_ALIAS "utime" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EFS_ALIAS "efs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ROUTER_ALIAS "router" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RIPNG_ALIAS "ripng" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ULP_ALIAS "ulp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IBM_DB2_ALIAS "ibm_db2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NCP_ALIAS "ncp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TIMED_ALIAS "timed" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TEMPO_ALIAS "tempo" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STX_ALIAS "stx" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CUSTIX_ALIAS "custix" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRC_SERV_ALIAS "irc_serv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COURIER_ALIAS "courier" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CONFERENCE_ALIAS "conference" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETNEWS_ALIAS "netnews" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETWALL_ALIAS "netwall" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WINDREAM_ALIAS "windream" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IIOP_ALIAS "iiop" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPALIS_RDV_ALIAS "opalis_rdv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NMSP_ALIAS "nmsp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GDOMAP_ALIAS "gdomap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APERTUS_LDP_ALIAS "apertus_ldp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUCP_ALIAS "uucp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUCP_RLOGIN_ALIAS "uucp_rlogin" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMMERCE_ALIAS "commerce" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KLOGIN_ALIAS "klogin" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KSHELL_ALIAS "kshell" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APPLEQTCSRVR_ALIAS "appleqtcsrvr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCPV6_CLIENT_ALIAS "dhcpv6_client" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCPV6_SERVER_ALIAS "dhcpv6_server" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AFPOVERTCP_ALIAS "afpovertcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDFP_ALIAS "idfp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NEW_RWHO_ALIAS "new_rwho" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CYBERCASH_ALIAS "cybercash" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEVSHR_NTS_ALIAS "devshr_nts" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PIRP_ALIAS "pirp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DSF_ALIAS "dsf" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REMOTEFS_ALIAS "remotefs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OPENVMS_SYSIPC_ALIAS "openvms_sysipc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SDNSKMP_ALIAS "sdnskmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TEEDTAP_ALIAS "teedtap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RMONITOR_ALIAS "rmonitor" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MONITOR_ALIAS "monitor" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CHSHELL_ALIAS "chshell" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NNTPS_ALIAS "nntps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_9PFS_ALIAS "9pfs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WHOAMI_ALIAS "whoami" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_STREETTALK_ALIAS "streettalk" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BANYAN_RPC_ALIAS "banyan_rpc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MS_SHUTTLE_ALIAS "ms_shuttle" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MS_ROME_ALIAS "ms_rome" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_METER_ALIAS "meter" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SONAR_ALIAS "sonar" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BANYAN_VIP_ALIAS "banyan_vip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTP_AGENT_ALIAS "ftp_agent" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VEMMI_ALIAS "vemmi" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPCD_ALIAS "ipcd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VNAS_ALIAS "vnas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPDD_ALIAS "ipdd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DECBSRV_ALIAS "decbsrv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SNTP_HEARTBEAT_ALIAS "sntp_heartbeat" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BDP_ALIAS "bdp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCC_SECURITY_ALIAS "scc_security" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PHILIPS_VC_ALIAS "philips_vc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KEYSERVER_ALIAS "keyserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PASSWORD_CHG_ALIAS "password_chg" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUBMISSION_ALIAS "submission" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CAL_ALIAS "cal" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EYELINK_ALIAS "eyelink" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TNS_CML_ALIAS "tns_cml" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTP_ALT_ALIAS "http_alt" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EUDORA_SET_ALIAS "eudora_set" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HTTP_RPC_EPMAP_ALIAS "http_rpc_epmap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TPIP_ALIAS "tpip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CAB_PROTOCOL_ALIAS "cab_protocol" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMSD_ALIAS "smsd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PTCNAMESERVICE_ALIAS "ptcnameservice" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_WEBSRVRMG3_ALIAS "sco_websrvrmg3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACP_ALIAS "acp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IPCSERVER_ALIAS "ipcserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SYSLOG_CONN_ALIAS "syslog_conn" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XMLRPC_BEEP_ALIAS "xmlrpc_beep" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDXP_ALIAS "idxp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TUNNEL_ALIAS "tunnel" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SOAP_BEEP_ALIAS "soap_beep" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_URM_ALIAS "urm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NQS_ALIAS "nqs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SIFT_UFT_ALIAS "sift_uft" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPMP_TRAP_ALIAS "npmp_trap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPMP_LOCAL_ALIAS "npmp_local" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NPMP_GUI_ALIAS "npmp_gui" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HMMP_IND_ALIAS "hmmp_ind" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HMMP_OP_ALIAS "hmmp_op" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SSHELL_ALIAS "sshell" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_INETMGR_ALIAS "sco_inetmgr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_SYSMGR_ALIAS "sco_sysmgr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_DTMGR_ALIAS "sco_dtmgr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEI_ICDA_ALIAS "dei_icda" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COMPAQ_EVM_ALIAS "compaq_evm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SCO_WEBSRVRMGR_ALIAS "sco_websrvrmgr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ESCP_IP_ALIAS "escp_ip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_COLLABORATOR_ALIAS "collaborator" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OOB_WS_HTTP_ALIAS "oob_ws_http" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASF_RMCP_ALIAS "asf_rmcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CRYPTOADMIN_ALIAS "cryptoadmin" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEC_DLM_ALIAS "dec_dlm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASIA_ALIAS "asia" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PASSGO_TIVOLI_ALIAS "passgo_tivoli" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QMQP_ALIAS "qmqp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_3COM_AMP3_ALIAS "3com_amp3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RDA_ALIAS "rda" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BMPP_ALIAS "bmpp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SERVSTAT_ALIAS "servstat" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GINAD_ALIAS "ginad" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RLZDBASE_ALIAS "rlzdbase" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LDAPS_ALIAS "ldaps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LANSERVER_ALIAS "lanserver" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MCNS_SEC_ALIAS "mcns_sec" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSDP_ALIAS "msdp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_SPS_ALIAS "entrust_sps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REPCMD_ALIAS "repcmd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ESRO_EMSDP_ALIAS "esro_emsdp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SANITY_ALIAS "sanity" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DWR_ALIAS "dwr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PSSC_ALIAS "pssc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LDP_ALIAS "ldp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCP_FAILOVER_ALIAS "dhcp_failover" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RRP_ALIAS "rrp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CADVIEW_3D_ALIAS "cadview_3d" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OBEX_ALIAS "obex" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IEEE_MMS_ALIAS "ieee_mms" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HELLO_PORT_ALIAS "hello_port" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REPSCMD_ALIAS "repscmd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AODV_ALIAS "aodv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TINC_ALIAS "tinc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SPMP_ALIAS "spmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RMC_ALIAS "rmc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TENFOLD_ALIAS "tenfold" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAC_SRVR_ADMIN_ALIAS "mac_srvr_admin" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HAP_ALIAS "hap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PFTP_ALIAS "pftp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PURENOISE_ALIAS "purenoise" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OOB_WS_HTTPS_ALIAS "oob_ws_https" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASF_SECURE_RMCP_ALIAS "asf_secure_rmcp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUN_DR_ALIAS "sun_dr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MDQS_ALIAS "mdqs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DOOM_ALIAS "doom" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DISCLOSE_ALIAS "disclose" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MECOMM_ALIAS "mecomm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MEREGISTER_ALIAS "meregister" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VACDSM_SWS_ALIAS "vacdsm_sws" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VACDSM_APP_ALIAS "vacdsm_app" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VPPS_QUA_ALIAS "vpps_qua" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CIMPLEX_ALIAS "cimplex" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACAP_ALIAS "acap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DCTP_ALIAS "dctp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VPPS_VIA_ALIAS "vpps_via" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VPP_ALIAS "vpp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GGF_NCP_ALIAS "ggf_ncp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MRM_ALIAS "mrm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_AAAS_ALIAS "entrust_aaas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_AAMS_ALIAS "entrust_aams" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XFR_ALIAS "xfr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CORBA_IIOP_ALIAS "corba_iiop" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CORBA_IIOP_SSL_ALIAS "corba_iiop_ssl" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MDC_PORTMAPPER_ALIAS "mdc_portmapper" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HCP_WISMAR_ALIAS "hcp_wismar" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ASIPREGISTRY_ALIAS "asipregistry" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_REALM_RUSD_ALIAS "realm_rusd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NMAP_ALIAS "nmap" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VATP_ALIAS "vatp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MSEXCH_ROUTING_ALIAS "msexch_routing" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HYPERWAVE_ISP_ALIAS "hyperwave_isp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CONNENDP_ALIAS "connendp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_HA_CLUSTER_ALIAS "ha_cluster" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IEEE_MMS_SSL_ALIAS "ieee_mms_ssl" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RUSHD_ALIAS "rushd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_UUIDGEN_ALIAS "uuidgen" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OLSR_ALIAS "olsr" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACCESSNETWORK_ALIAS "accessnetwork" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EPP_ALIAS "epp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LMP_ALIAS "lmp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_BEEP_ALIAS "iris_beep" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ELCSD_ALIAS "elcsd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_AGENTX_ALIAS "agentx" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SILC_ALIAS "silc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BORLAND_DSJ_ALIAS "borland_dsj" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_KMSH_ALIAS "entrust_kmsh" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTRUST_ASH_ALIAS "entrust_ash" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CISCO_TDP_ALIAS "cisco_tdp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TBRPF_ALIAS "tbrpf" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_XPC_ALIAS "iris_xpc" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_XPCS_ALIAS "iris_xpcs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IRIS_LWZ_ALIAS "iris_lwz" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PANA_ALIAS "pana" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETVIEWDM1_ALIAS "netviewdm1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETVIEWDM2_ALIAS "netviewdm2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETVIEWDM3_ALIAS "netviewdm3" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETGW_ALIAS "netgw" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETRCS_ALIAS "netrcs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FLEXLM_ALIAS "flexlm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FUJITSU_DEV_ALIAS "fujitsu_dev" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RIS_CM_ALIAS "ris_cm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KERBEROS_ADM_ALIAS "kerberos_adm" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RFILE_ALIAS "rfile" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_LOADAV_ALIAS "loadav" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KERBEROS_IV_ALIAS "kerberos_iv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PUMP_ALIAS "pump" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QRH_ALIAS "qrh" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RRH_ALIAS "rrh" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TELL_ALIAS "tell" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NLOGIN_ALIAS "nlogin" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CON_ALIAS "con" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NS_ALIAS "ns" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RXE_ALIAS "rxe" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_QUOTAD_ALIAS "quotad" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CYCLESERV_ALIAS "cycleserv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OMSERV_ALIAS "omserv" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WEBSTER_ALIAS "webster" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PHONEBOOK_ALIAS "phonebook" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VID_ALIAS "vid" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CADLOCK_ALIAS "cadlock" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RTIP_ALIAS "rtip" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CYCLESERV2_ALIAS "cycleserv2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SUBMIT_ALIAS "submit" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NOTIFY_ALIAS "notify" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RPASSWD_ALIAS "rpasswd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACMAINT_DBD_ALIAS "acmaint_dbd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ENTOMB_ALIAS "entomb" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACMAINT_TRANSD_ALIAS "acmaint_transd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WPAGES_ALIAS "wpages" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MULTILING_HTTP_ALIAS "multiling_http" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_WPGS_ALIAS "wpgs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MDBS_DAEMON_ALIAS "mdbs_daemon" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DEVICE_ALIAS "device" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MBAP_S_ALIAS "mbap_s" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FCP_UDP_ALIAS "fcp_udp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ITM_MCELL_S_ALIAS "itm_mcell_s" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PKIX_3_CA_RA_ALIAS "pkix_3_ca_ra" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONF_SSH_ALIAS "netconf_ssh" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONF_BEEP_ALIAS "netconf_beep" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONFSOAPHTTP_ALIAS "netconfsoaphttp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NETCONFSOAPBEEP_ALIAS "netconfsoapbeep" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DHCP_FAILOVER2_ALIAS "dhcp_failover2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GDOI_ALIAS "gdoi" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_DOMAIN_S_ALIAS "domain_s" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ISCSI_ALIAS "iscsi" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OWAMP_CONTROL_ALIAS "owamp_control" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TWAMP_CONTROL_ALIAS "twamp_control" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_RSYNC_ALIAS "rsync" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ICLCNET_LOCATE_ALIAS "iclcnet_locate" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ICLCNET_SVINFO_ALIAS "iclcnet_svinfo" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_ACCESSBUILDER_ALIAS "accessbuilder" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CDDBP_ALIAS "cddbp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_OMGINITIALREFS_ALIAS "omginitialrefs" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SMPNAMERES_ALIAS "smpnameres" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDEAFARM_DOOR_ALIAS "ideafarm_door" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_IDEAFARM_PANIC_ALIAS "ideafarm_panic" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_KINK_ALIAS "kink" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_XACT_BACKUP_ALIAS "xact_backup" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APEX_MESH_ALIAS "apex_mesh" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APEX_EDGE_ALIAS "apex_edge" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTPS_DATA_ALIAS "ftps_data" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_FTPS_ALIAS "ftps" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_NAS_ALIAS "nas" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_TELNETS_ALIAS "telnets" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_POP3S_ALIAS "pop3s" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_VSINET_ALIAS "vsinet" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_MAITRD_ALIAS "maitrd" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BUSBOY_ALIAS "busboy" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PUPARP_ALIAS "puparp" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_GARCON_ALIAS "garcon" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_APPLIX_ALIAS "applix" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_PUPROUTER_ALIAS "puprouter" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_CADLOCK2_ALIAS "cadlock2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_SURF_ALIAS "surf" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EXP1_ALIAS "exp1" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_EXP2_ALIAS "exp2" // was generated by MMTCrawler on 8 mar 2016 @luongnv89
#define PROTO_BLACKJACK_ALIAS "blackjack" // was generated by MMTCrawler on 8 mar 2016 @luongnv89

#define PROTO_CLASS_UNKOWN         0
#define PROTO_CLASS_WEB            1
#define PROTO_CLASS_P2P            2
#define PROTO_CLASS_GAMING         3
#define PROTO_CLASS_STREAMING      4
#define PROTO_CLASS_CONVERSATIONAL 5
#define PROTO_CLASS_MAIL           6
#define PROTO_CLASS_FILETRANSFER   7
#define PROTO_CLASS_CLOUD_STORAGE  8
#define PROTO_CLASS_DDL            9
#define PROTO_CLASS_NETWORK       10
#define PROTO_CLASS_TUNNEL        11
#define PROTO_CLASS_DB            12
#define PROTO_CLASS_REMOTE        13
#define PROTO_CLASS_MISC          14
#define PROTO_CLASS_CDN           15

#define PROTO_CLASS_LABELS \
 "Unkown",                 \
 "Web",                    \
 "P2P",                    \
 "Gaming",                 \
 "Streaming",              \
 "Conversational",         \
 "Mail",                   \
 "FileTransfer",           \
 "CloudStorage",           \
 "DirectDownloadLink",     \
 "Network",                \
 "Tunnelling",             \
 "DataBase",               \
 "Remote",                 \
 "Misc",                   \
 "CDN"

#ifdef __cplusplus
}
#endif
#endif //MMT_TCPIP_PROTOCOLS
