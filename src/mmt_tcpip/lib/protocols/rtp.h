/*
 * File:   rtp.h
 * Author: montimage
 *
 * Created on 3 août 2011, 14:08
 */

#ifndef RTP_H
#define	RTP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
#include "mmt_quality_estimation_utilities.h"

#define MMT_Window_Rank 3
#define MMT_Window_Width 8
#define MMT_Quality_Index_Estimation_Rate 5000000 /**< Frequency of the quality estimation in usec */
#define MMTRTP_MINIMAL_REPORTING_COUNT 32 /**< The minimal number of packets for making a quality estimation*/
#define MAX_RTP_PT 256 /**< Max number of RTP payload types. */

    struct indexes {
        uint16_t index : MMT_Window_Rank;
    };

    struct rtphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t cc : 4, ext : 1, padding : 1, version : 2;
#elif BYTE_ORDER == BIG_ENDIAN
        uint8_t version : 2, padding : 1, ext : 1, cc : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t pt : 7, mark : 1;
#elif BYTE_ORDER == BIG_ENDIAN
        uint8_t mark : 1, pt : 7;
#else
#error "BYTE_ORDER must be defined"
#endif
        uint16_t seq;
        uint32_t tstmp;
        uint32_t ssrc;
        uint32_t csrc;
    };

    typedef struct rtp_payload_mime_type_struct {
        int encoding_code;
        int media_type;
        int clock_rate;
        int isstatic;
        char * encoding_name;
    } rtp_payload_mime_type_t;

    typedef struct multimedia_quality_index_context_struct {
        uint32_t do_estimate;
        struct timeval last_quality_estimation_time;
        uint32_t media_jitter_us; //metric: RTP jitter in microseconds: this is the last two packets inter arrival delay
        uint32_t media_delay_us; //metric
        uint32_t media_packet_count_cumulative;
        uint32_t nb_out_of_order_cumulative; //metric
        uint32_t nb_order_error_cumulative; //metric
        uint32_t nb_lost_cumulative; //metric
        uint32_t nb_duplicate_cumulative; //metric
        uint32_t loss_burst_nb_cumulative; //metric

        //Will be used within the estimation rules
        double jitter_ms;
        double delay_ms;
        double loss_rate;
        double loss_burstiness_rate;
        double order_error_rate;
        double out_of_order_rate;
        double duplicate_rate;

        double quality_index;

        application_quality_estimation_internal_t * quality_index_internal_struct;
    }multimedia_quality_index_context_t;


    typedef struct multimedia_session_context_struct {
        uint32_t last_tstmp;
        struct timeval last_arrival_time;

        uint32_t media_jitter_us; //metric: RTP jitter in microseconds: this is the last two packets inter arrival delay
        uint32_t jitter_us; //metric: jitter in microseconds: this is the last two packets inter arrival delay
        uint32_t delay_us; // metric: delay in microseconds: this is the last two packets inter arrival delay
        uint16_t nb_out_of_order; //metric
        uint16_t nb_order_error; //metric
        uint16_t nb_lost; //metric
        uint16_t nb_duplicate; //metric
        uint16_t loss_burst_size; //metric
        uint16_t loss_observed_burst_size; //metric

        uint16_t last_seqnb;
        uint16_t low_seqnb;
        uint16_t high_seqnb;
        uint16_t nb_missed;

        struct indexes index_low;
        struct indexes index_high;
        uint16_t seqnb_cache[MMT_Window_Width];

    }multimedia_session_context_t;

    struct rtp_session_data_struct {
        generic_session_data_analysis_function rtp_data_analysis; //for performance reasons! this will point to the function to be called for processing session data
        generic_session_quality_index_estimation_function rtp_quality_index_estimation;

        uint8_t payload_type;
        rtp_payload_mime_type_t * mime_type;
        multimedia_session_context_t rtp_media_session_context;
        multimedia_quality_index_context_t rtp_quality_index_context;
//        uint8_t payload_type_code;
//        uint8_t media_type;
//        uint32_t clock_rate;

//        uint32_t last_tstmp;
//        struct timeval last_arrival_time;
//
//        uint32_t media_jitter_us; //metric: RTP jitter in microseconds: this is the last two packets inter arrival delay
//        uint32_t jitter_us; //metric: jitter in microseconds: this is the last two packets inter arrival delay
//        uint32_t delay_us; // metric: delay in microseconds: this is the last two packets inter arrival delay
//
//        uint16_t last_seqnb;
//        uint16_t nb_out_of_order; //metric
//        uint16_t nb_order_error; //metric
//        uint16_t nb_lost; //metric
//        uint16_t nb_duplicate; //metric
//        uint16_t loss_burst_size; //metric
//        struct indexes index_low;
//        struct indexes index_high;
//        uint16_t low_seqnb;
//        uint16_t high_seqnb;
//        uint16_t nb_missed;
//        uint16_t seqnb_cache[windowwidth];
    };

#define AUDIO           1
#define VIDEO           2
#define AUDIO_VIDEO     3

    enum {//Internal format codes; non zero values! sould not mix with Payload_type values
        MMT_RTP_FORMAT_PCMU = 1,
        MMT_RTP_FORMAT_GSM,
        MMT_RTP_FORMAT_G723,
        MMT_RTP_FORMAT_DVI4,
        MMT_RTP_FORMAT_LPC,
        MMT_RTP_FORMAT_PCMA,
        MMT_RTP_FORMAT_G722,
        MMT_RTP_FORMAT_L16,
        MMT_RTP_FORMAT_QCELP,
        MMT_RTP_FORMAT_CN,
        MMT_RTP_FORMAT_MPA,
        MMT_RTP_FORMAT_G728,
        MMT_RTP_FORMAT_G729,
        MMT_RTP_FORMAT_G726_40,
        MMT_RTP_FORMAT_G726_32,
        MMT_RTP_FORMAT_G726_24,
        MMT_RTP_FORMAT_G726_16,
        MMT_RTP_FORMAT_G729D,
        MMT_RTP_FORMAT_G729E,
        MMT_RTP_FORMAT_GSM_EFR,
        MMT_RTP_FORMAT_L8,
        MMT_RTP_FORMAT_RED,
        MMT_RTP_FORMAT_VDVI,
        MMT_RTP_FORMAT_CelB,
        MMT_RTP_FORMAT_JPEG,
        MMT_RTP_FORMAT_nv,
        MMT_RTP_FORMAT_H261,
        MMT_RTP_FORMAT_MPV,
        MMT_RTP_FORMAT_MP2T,
        MMT_RTP_FORMAT_H263,
        MMT_RTP_FORMAT_H263_1998,
        MMT_RTP_FORMAT_H264,
    };

    int init_rtp_proto_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* RTP_H */
