#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "rtp.h"
#include "packet_processing.h"
#ifndef _MMT_BUILD_SDK
#include "mmt_quality_estimation_calculation.h"
#endif /* _MMT_BUILD_SDK */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define RTP_MAX_OUT_OF_ORDER 11

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

double dummy_estimation(application_quality_estimation_internal_t * app_internal_struct) {
    return 0.0;
}

static rtp_payload_mime_type_t static_rtp_payload_mime_types[MAX_RTP_PT] = {
     [0] = { MMT_RTP_FORMAT_PCMU,  AUDIO,        8000, 1, "PCMU"  },
     [3] = { MMT_RTP_FORMAT_GSM,   AUDIO,        8000, 1, "GSM"   },
     [4] = { MMT_RTP_FORMAT_G723,  AUDIO,        8000, 1, "G723"  },
     [5] = { MMT_RTP_FORMAT_DVI4,  AUDIO,        8000, 1, "DVI4"  },
     [6] = { MMT_RTP_FORMAT_DVI4,  AUDIO,       16000, 1, "DVI4"  },
     [7] = { MMT_RTP_FORMAT_LPC,   AUDIO,        8000, 1, "LPC"   },
     [8] = { MMT_RTP_FORMAT_PCMA,  AUDIO,        8000, 1, "PCMA"  },
     [9] = { MMT_RTP_FORMAT_G722,  AUDIO,        8000, 1, "G722"  },
    [10] = { MMT_RTP_FORMAT_L16,   AUDIO,       44100, 1, "L16"   },
    [11] = { MMT_RTP_FORMAT_L16,   AUDIO,       44100, 1, "L16"   },
    [12] = { MMT_RTP_FORMAT_QCELP, AUDIO,        8000, 1, "QCELP" },
    [13] = { MMT_RTP_FORMAT_CN,    AUDIO,        8000, 1, "CN"    },
    [14] = { MMT_RTP_FORMAT_MPA,   AUDIO,       90000, 1, "MPA"   },
    [15] = { MMT_RTP_FORMAT_G728,  AUDIO,        8000, 1, "G728"  },
    [16] = { MMT_RTP_FORMAT_DVI4,  AUDIO,       11025, 1, "DVI4"  },
    [17] = { MMT_RTP_FORMAT_DVI4,  AUDIO,       22050, 1, "DVI4"  },
    [18] = { MMT_RTP_FORMAT_G729,  AUDIO,        8000, 1, "G729"  },
    [25] = { MMT_RTP_FORMAT_CelB,  VIDEO,       90000, 1, "CelB"  },
    [26] = { MMT_RTP_FORMAT_JPEG,  VIDEO,       90000, 1, "JPEG"  },
    [28] = { MMT_RTP_FORMAT_nv,    VIDEO,       90000, 1, "nv"    },
    [31] = { MMT_RTP_FORMAT_H261,  VIDEO,       90000, 1, "H261"  },
    [32] = { MMT_RTP_FORMAT_MPV,   VIDEO,       90000, 1, "MPV"   },
    [33] = { MMT_RTP_FORMAT_MP2T,  AUDIO_VIDEO, 90000, 1, "PM2T"  },
    [34] = { MMT_RTP_FORMAT_H263,  VIDEO,       90000, 1, "H263"  },
};


#ifndef _MMT_BUILD_SDK
void update_multimedia_quality_index_context(multimedia_quality_index_context_t * quality_index_context, multimedia_session_context_t * session_context) {
    int timediff = short_time_diff(&quality_index_context->last_quality_estimation_time, &session_context->last_arrival_time);

    quality_index_context->media_jitter_us = session_context->media_jitter_us;
    quality_index_context->nb_lost_cumulative += session_context->nb_lost;
    quality_index_context->media_packet_count_cumulative += 1;

    if (timediff > MMT_Quality_Index_Estimation_Rate) {
        quality_index_context->do_estimate = 1; //The estimation is enabled

        quality_index_context->jitter_ms = (double) quality_index_context->media_jitter_us / 1000.0;
        quality_index_context->loss_rate = (double) ((quality_index_context->nb_lost_cumulative * 100.0) / (quality_index_context->media_packet_count_cumulative + quality_index_context->nb_lost_cumulative));

        quality_index_context->last_quality_estimation_time = session_context->last_arrival_time;
    } else {
        quality_index_context->quality_index = 0.0;
    }

}
#endif /* _MMT_BUILD_SDK */

int rtp_version_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    *(uint8_t *) extracted_data->data = ((struct rtphdr *) & packet->data[proto_offset])->version;
    return 1;
}

int rtp_padding_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    *(uint8_t *) extracted_data->data = ((struct rtphdr *) & packet->data[proto_offset])->padding;
    return 1;
}

int rtp_extension_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    *(uint8_t *) extracted_data->data = ((struct rtphdr *) & packet->data[proto_offset])->ext;
    return 1;
}

int rtp_cc_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    *(uint8_t *) extracted_data->data = ((struct rtphdr *) & packet->data[proto_offset])->cc;
    return 1;
}

int rtp_marker_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    *(uint8_t *) extracted_data->data = ((struct rtphdr *) & packet->data[proto_offset])->mark;
    return 1;
}

int rtp_payload_type_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    *(uint8_t *) extracted_data->data = ((struct rtphdr *) & packet->data[proto_offset])->pt;
    return 1;
}

int rtp_csrc_list_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    int attribute_offset = extracted_data->position_in_packet;

    uint8_t i;
    uint8_t cc = ((struct rtphdr *) & packet->data[proto_offset])->cc * 4; //TODO: shifting is more optimal no?
    *((unsigned int *) extracted_data->data) = cc;
    for (i = 0; i < cc; i++) {
        *((unsigned int *) & ((u_char *) extracted_data->data)[sizeof (int) +i * 4]) = ntohl(*((unsigned int *) & packet->data[proto_offset + attribute_offset + i * 4]));
    }
    i = (cc) ? 1 : 0;
    return i;
}

int rtp_quality_index_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        //The jitter is calculated only if the payload type code is known
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_quality_index_context.quality_index != 0.0) {
            *(double *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_quality_index_context.quality_index;
            return 1;
        }
    }
    return 0;
}

int rtp_jitter_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        //The jitter is calculated only if the payload type code is known
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->mime_type->encoding_code) {
            *(uint32_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.media_jitter_us;
            return 1;
        }
    }
    return 0;
}

int rtp_inter_arrival_jitter_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        //The jitter is calculated only if the payload type code is known
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->mime_type->encoding_code) {
            *(uint32_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.jitter_us;
            return 1;
        }
    }
    return 0;
}

int rtp_inter_delay_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        //The jitter is calculated only if the payload type code is known
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->mime_type->encoding_code) {
            *(uint32_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.delay_us;
            return 1;
        }
    }
    return 0;
}

int rtp_loss_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_lost) {
            *(uint16_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_lost;
            return 1;
        }
    }
    return 0;
}

int rtp_burst_loss_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        //A burst is detected if the loss burst size is greater than ZERO and the loss is zero!
        //Yeah the size of the burst can only be detected at the end of consecutive loss occurences
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.loss_burst_size > 0) {
            *(uint16_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.loss_burst_size;
            return 1;
        }
    }
    return 0;
}

int rtp_nb_out_of_order_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_out_of_order) {
            *(uint16_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_out_of_order;
            return 1;
        }
    }
    return 0;
}

int rtp_order_error_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_order_error) {
            *(uint16_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_order_error;
            return 1;
        }
    }
    return 0;
}

int rtp_duplicate_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if ((struct rtp_session_data_struct *) packet->session->session_data[proto_index] != NULL) {
        if (((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_duplicate) {
            *(uint16_t *) extracted_data->data = ((struct rtp_session_data_struct *) packet->session->session_data[proto_index])->rtp_media_session_context.nb_duplicate;
            return 1;
        }
    }
    return 0;
}

void process_packet_loss_order(struct rtp_session_data_struct * rtp_session_data, int seqnb) {
    uint16_t diff_low, diff_high;
    uint32_t i;
    struct indexes temp_index;

    //reset the loss burst size to zero
    rtp_session_data->rtp_media_session_context.loss_burst_size = 0;

    //Set the last received sequence number to the newly received sequence number
    rtp_session_data->rtp_media_session_context.last_seqnb = seqnb;

    diff_high = seqnb - rtp_session_data->rtp_media_session_context.high_seqnb;
    diff_low = seqnb - rtp_session_data->rtp_media_session_context.low_seqnb;
    if ((rtp_session_data->rtp_media_session_context.nb_missed == 0) && (diff_high == 1)) { //No loss No reordering occurred, the indexes will not get changed.
        //Set the metrics to ZEROs
        //These are per packet calculated metrics, they should be set

        //The packet arrives in the right order
        rtp_session_data->rtp_media_session_context.nb_out_of_order = 0; //metric
        rtp_session_data->rtp_media_session_context.nb_order_error = 0; //metric
        //No loss & no duplication
        rtp_session_data->rtp_media_session_context.nb_lost = 0; //metric
        rtp_session_data->rtp_media_session_context.nb_duplicate = 0; //metric

        rtp_session_data->rtp_media_session_context.low_seqnb = seqnb;
        rtp_session_data->rtp_media_session_context.high_seqnb = seqnb;
        rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_low.index] = seqnb;

        rtp_session_data->rtp_media_session_context.loss_burst_size = rtp_session_data->rtp_media_session_context.loss_observed_burst_size;
        rtp_session_data->rtp_media_session_context.loss_observed_burst_size = 0;

    } else {
        //Out of order packet
        rtp_session_data->rtp_media_session_context.nb_out_of_order = 1; //metric

        //Set the metrics to ZEROs to clear what was set by previous packets
        //These metrics will get the right value in the following code
        rtp_session_data->rtp_media_session_context.nb_order_error = 0; //metric
        rtp_session_data->rtp_media_session_context.nb_lost = 0; //metric
        rtp_session_data->rtp_media_session_context.nb_duplicate = 0; //metric

        if ((diff_low > 0xFF00) && (diff_high > 0xFF00)) { // Order error (seqnb logically before lowseqnb)
            rtp_session_data->rtp_media_session_context.nb_order_error = 1;
        } else if ((diff_low < 0x00FF) && (diff_high > 0xFF00)) { //Either a duplicate or reception of a missed packet
            diff_low = seqnb - rtp_session_data->rtp_media_session_context.low_seqnb;
            if (rtp_session_data->rtp_media_session_context.seqnb_cache[(rtp_session_data->rtp_media_session_context.index_low.index + diff_low) % MMT_Window_Width] == 0) { //Reception of outoforder packet, it was considered as missed
                rtp_session_data->rtp_media_session_context.seqnb_cache[(rtp_session_data->rtp_media_session_context.index_low.index + diff_low) % MMT_Window_Width] = seqnb;
                rtp_session_data->rtp_media_session_context.nb_missed--;
                if (rtp_session_data->rtp_media_session_context.nb_missed == 0) {
                    rtp_session_data->rtp_media_session_context.index_low.index = rtp_session_data->rtp_media_session_context.index_high.index;
                    rtp_session_data->rtp_media_session_context.low_seqnb = rtp_session_data->rtp_media_session_context.high_seqnb;
                }
            } else { //This is a duplicate
                rtp_session_data->rtp_media_session_context.nb_duplicate = 1;
            }
        } else if ((diff_low < 0x00FF) && (diff_high < 0x00FF)) {
            if (diff_high == 1) {
                rtp_session_data->rtp_media_session_context.high_seqnb = seqnb;
                rtp_session_data->rtp_media_session_context.index_high.index++;
                if (rtp_session_data->rtp_media_session_context.index_high.index == rtp_session_data->rtp_media_session_context.index_low.index) {
                    //This is wrap around, verify there is no missed packet
                    if (rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_low.index] == 0) {
                        rtp_session_data->rtp_media_session_context.nb_missed--;
                        rtp_session_data->rtp_media_session_context.nb_lost = 1;
                        rtp_session_data->rtp_media_session_context.loss_observed_burst_size += rtp_session_data->rtp_media_session_context.nb_lost;
                    }

                    if (rtp_session_data->rtp_media_session_context.nb_missed > 0) {
                        //Update the index of low seqnb
                        rtp_session_data->rtp_media_session_context.low_seqnb++;
                        //Update the low index
                        rtp_session_data->rtp_media_session_context.index_low.index++;
                    } else { //No more missed packets!
                        //The low and high indexes are the same
                        //The low and high seqnb are the same as well
                        rtp_session_data->rtp_media_session_context.low_seqnb = rtp_session_data->rtp_media_session_context.high_seqnb;
                        //Just ensure nb_missed is zero
                        rtp_session_data->rtp_media_session_context.nb_missed = 0;
                    }
                }
                //Update the cache value of high index
                rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_high.index] = rtp_session_data->rtp_media_session_context.high_seqnb;
            } else { //diff_high > 1; this means there are some missing packets
                //There are different cases:
                //1- if diff_high >= windowwidth
                //2- if diff_low >= windowwidth
                //3- diff_low < windowwidth
                //diff_low = seqnb - rtp_session_data->rtp_media_session_context.low_seqnb;
                if (diff_high >= MMT_Window_Width) {
                    rtp_session_data->rtp_media_session_context.nb_lost = diff_high - MMT_Window_Width + rtp_session_data->rtp_media_session_context.nb_missed;
                    rtp_session_data->rtp_media_session_context.loss_burst_size = rtp_session_data->rtp_media_session_context.nb_missed + rtp_session_data->rtp_media_session_context.loss_observed_burst_size;

                    rtp_session_data->rtp_media_session_context.loss_observed_burst_size = diff_high - MMT_Window_Width;
                    rtp_session_data->rtp_media_session_context.nb_missed = MMT_Window_Width - 1;

                    //Set the cache to zeroes
                    for (i = 0; i < MMT_Window_Width; i++) {
                        rtp_session_data->rtp_media_session_context.seqnb_cache[i] = 0;
                    }

                    rtp_session_data->rtp_media_session_context.high_seqnb = seqnb;
                    rtp_session_data->rtp_media_session_context.low_seqnb = seqnb - MMT_Window_Width + 1;
                    rtp_session_data->rtp_media_session_context.index_high.index = 0; //We can chose the index as there will only be one non zero
                    rtp_session_data->rtp_media_session_context.index_low.index = rtp_session_data->rtp_media_session_context.index_high.index + 1;
                    rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_high.index] = seqnb; //This is the only received packet in the cache
                } else if (diff_low >= MMT_Window_Width) {
                    rtp_session_data->rtp_media_session_context.nb_missed += diff_high - 1; // We do not count the current packet that's why there is - 1
                    rtp_session_data->rtp_media_session_context.nb_lost = 0;
                    //First set to zero the indexed values between high index and low index
                    temp_index.index = rtp_session_data->rtp_media_session_context.index_high.index + 1;
                    while (temp_index.index != rtp_session_data->rtp_media_session_context.index_low.index) {
                        rtp_session_data->rtp_media_session_context.seqnb_cache[temp_index.index] = 0;
                        temp_index.index++;
                    }

                    rtp_session_data->rtp_media_session_context.high_seqnb = seqnb;
                    rtp_session_data->rtp_media_session_context.index_high.index += diff_high;
                    temp_index.index = rtp_session_data->rtp_media_session_context.index_high.index - rtp_session_data->rtp_media_session_context.index_low.index;
                    for (i = 0; i <= temp_index.index; i++) {
                        if (rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_low.index] == 0) {
                            rtp_session_data->rtp_media_session_context.nb_lost++;
                            rtp_session_data->rtp_media_session_context.loss_observed_burst_size++;
                            rtp_session_data->rtp_media_session_context.nb_missed--;
                        } else {
                            rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_low.index] = 0;
                        }
                        rtp_session_data->rtp_media_session_context.index_low.index++;
                        rtp_session_data->rtp_media_session_context.low_seqnb++;
                    }
                    rtp_session_data->rtp_media_session_context.loss_burst_size = rtp_session_data->rtp_media_session_context.loss_observed_burst_size;
                    rtp_session_data->rtp_media_session_context.loss_observed_burst_size = 0;
                    rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_high.index] = seqnb;
                } else {// No wrap arround
                    rtp_session_data->rtp_media_session_context.nb_missed += diff_high - 1; // We do not count the current packet that's why there is - 1
                    rtp_session_data->rtp_media_session_context.high_seqnb = seqnb;
                    rtp_session_data->rtp_media_session_context.index_high.index += diff_high;
                    //Update the cache value of high index
                    rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_high.index] = rtp_session_data->rtp_media_session_context.high_seqnb;
                    //Mark the missed indexex
                    temp_index.index = rtp_session_data->rtp_media_session_context.index_low.index + 1;
                    for (i = 1; i < diff_high; i++) {
                        rtp_session_data->rtp_media_session_context.seqnb_cache[temp_index.index] = 0;
                        temp_index.index++;
                    }
                }
            }
        } else {
            //Unexpected jump in the sequence number!!! to avoid stucking in an unstable state:
            //   report missed sequence numbers as loss
            //   set the metrics to zero and start over
            rtp_session_data->rtp_media_session_context.nb_lost = rtp_session_data->rtp_media_session_context.nb_missed;
            rtp_session_data->rtp_media_session_context.loss_burst_size = rtp_session_data->rtp_media_session_context.nb_missed + rtp_session_data->rtp_media_session_context.loss_observed_burst_size;

            rtp_session_data->rtp_media_session_context.loss_observed_burst_size = 0;
            rtp_session_data->rtp_media_session_context.nb_missed = 0;

            //Set the cache to zeroes
            for (i = 0; i < MMT_Window_Width; i++) {
                rtp_session_data->rtp_media_session_context.seqnb_cache[i] = 0;
            }

            rtp_session_data->rtp_media_session_context.high_seqnb = seqnb;
            rtp_session_data->rtp_media_session_context.low_seqnb = seqnb;
            rtp_session_data->rtp_media_session_context.index_high.index = 0; //We can choose the index as there will only be one non zero
            rtp_session_data->rtp_media_session_context.index_low.index = rtp_session_data->rtp_media_session_context.index_high.index;
            rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_low.index] = seqnb; //This is the only received packet in the cache
        }
    }
}

void process_packet_timediff_jitter(ipacket_t * ipacket, struct rtp_session_data_struct * rtp_session_data, uint32_t timestmp) {
    if (rtp_session_data->mime_type->encoding_code) {
        uint32_t timearrivaldiff = short_time_diff(&rtp_session_data->rtp_media_session_context.last_arrival_time, &ipacket->p_hdr->ts);
        uint32_t timestmpdiff = timestmp - rtp_session_data->rtp_media_session_context.last_tstmp;

        double timestmpdiff_usec = (double)(timestmpdiff * 1000000) / rtp_session_data->mime_type->clock_rate;
        timestmpdiff = (uint32_t) timestmpdiff_usec;

        int diff = abs(timearrivaldiff - timestmpdiff);

        double new_jitter = (double) rtp_session_data->rtp_media_session_context.media_jitter_us + ((double) diff - (double) rtp_session_data->rtp_media_session_context.media_jitter_us) / 16;

        rtp_session_data->rtp_media_session_context.media_jitter_us = (uint32_t) new_jitter;

        int std_diff = abs(timearrivaldiff - rtp_session_data->rtp_media_session_context.delay_us);
        double new_std_jitter = (double) rtp_session_data->rtp_media_session_context.jitter_us + ((double) std_diff - (double) rtp_session_data->rtp_media_session_context.jitter_us) / 16;

        rtp_session_data->rtp_media_session_context.jitter_us = (uint32_t) new_std_jitter;

        rtp_session_data->rtp_media_session_context.delay_us = timearrivaldiff;

    }

    //Finaly update the las timestamp and reception time
    rtp_session_data->rtp_media_session_context.last_arrival_time = ipacket->p_hdr->ts;
    rtp_session_data->rtp_media_session_context.last_tstmp = timestmp;
}

int rtp_session_data_processing(ipacket_t * ipacket, unsigned index) {
    struct rtp_session_data_struct * rtp_session_data = ipacket->session->session_data[index];
    int offset = get_packet_offset_at_index(ipacket, index);
    struct rtphdr * rtp_hdr = (struct rtphdr *) &ipacket->data[offset];

    uint16_t new_seqnb = ntohs(rtp_hdr->seq);
    process_packet_loss_order(rtp_session_data, new_seqnb);

    process_packet_timediff_jitter(ipacket, rtp_session_data, ntohl(rtp_hdr->tstmp));

#ifndef _MMT_BUILD_SDK
    update_multimedia_quality_index_context(&rtp_session_data->rtp_quality_index_context, &rtp_session_data->rtp_media_session_context);

    if (rtp_session_data->rtp_quality_index_context.do_estimate) {
        //Call the estimation function
        if (rtp_session_data->rtp_quality_index_context.media_packet_count_cumulative >= MMTRTP_MINIMAL_REPORTING_COUNT) {
            rtp_session_data->rtp_quality_index_context.quality_index = rtp_session_data->rtp_quality_index_estimation(rtp_session_data->rtp_quality_index_context.quality_index_internal_struct);
        }

        //Reset the estimation context for a new sampling period
        rtp_session_data->rtp_quality_index_context.do_estimate = 0;
        rtp_session_data->rtp_quality_index_context.media_packet_count_cumulative = 0;
        rtp_session_data->rtp_quality_index_context.nb_lost_cumulative = 0;
    }
#endif /* _MMT_BUILD_SDK */

    return 0;
}

int rtp_initial_data_processing(ipacket_t * ipacket, unsigned index) {
    struct rtp_session_data_struct * rtp_session_data = ipacket->session->session_data[index];
    int offset = get_packet_offset_at_index(ipacket, index);
    struct rtphdr * rtp_hdr = (struct rtphdr *) &ipacket->data[offset];
    int i;
    uint16_t new_seqnb = ntohs(rtp_hdr->seq);

    //This is the first packet

    for (i = 0; i < MMT_Window_Width; i++)
        rtp_session_data->rtp_media_session_context.seqnb_cache[i] = 0; //Set cache to zeros

    rtp_session_data->rtp_media_session_context.low_seqnb = new_seqnb;
    rtp_session_data->rtp_media_session_context.high_seqnb = new_seqnb;
    rtp_session_data->rtp_media_session_context.seqnb_cache[rtp_session_data->rtp_media_session_context.index_low.index] = new_seqnb;


    //set the payload type code, and properties
    //If this is a static payload type the values will be non zero! code of zero means unknown!
    rtp_session_data->payload_type = rtp_hdr->pt;
    /*
        rtp_session_data->payload_type_code = static_rtp_payload_mime_types[rtp_hdr->pt].encoding_code;
        rtp_session_data->media_type = static_rtp_payload_mime_types[rtp_hdr->pt].media_type;
        rtp_session_data->clock_rate = static_rtp_payload_mime_types[rtp_hdr->pt].clock_rate;
     */
    rtp_session_data->mime_type = &static_rtp_payload_mime_types[rtp_hdr->pt];

    ////////////////////////////////////////////TODO: replace by generic function
#ifndef _MMT_BUILD_SDK
    application_quality_estimation_internal_t * app_internal_struct;
    app_internal_struct = init_new_internal_application_quality_estimation_struct(init_application_quality_estimation_structures("rtp_q_inf_rules.xml"));
    if (app_internal_struct != NULL) {
        //These are part of the initialization for a given protocol
        rtp_session_data->rtp_quality_index_context.quality_index_internal_struct = app_internal_struct;
        app_internal_struct->metric_values[1] = &rtp_session_data->rtp_quality_index_context.loss_rate;
        app_internal_struct->metric_values[0] = &rtp_session_data->rtp_quality_index_context.jitter_ms;

        //Every thing is OK, Set the quality estimation routine
        rtp_session_data->rtp_quality_index_estimation = estimate_quality_index;
    }
    rtp_session_data->rtp_quality_index_context.last_quality_estimation_time = ipacket->p_hdr->ts;
#endif /* _MMT_BUILD_SDK */

    rtp_session_data->rtp_media_session_context.last_tstmp = ntohl(rtp_hdr->tstmp);
    rtp_session_data->rtp_media_session_context.last_arrival_time = ipacket->p_hdr->ts;

    rtp_session_data->rtp_data_analysis = rtp_session_data_processing;

    return 0;
}

void rtp_session_data_init(ipacket_t * ipacket, unsigned index) {
    struct rtp_session_data_struct * rtp_session_data = (struct rtp_session_data_struct *) mmt_malloc(sizeof (struct rtp_session_data_struct));

    memset(rtp_session_data, 0, sizeof (struct rtp_session_data_struct));
    ipacket->session->session_data[index] = rtp_session_data;
    //Set the processing function to initial processing this will deal with the first incoming packet(s)
    rtp_session_data->rtp_data_analysis = rtp_initial_data_processing;

#ifndef _MMT_BUILD_SDK
    rtp_session_data->rtp_quality_index_estimation = dummy_estimation;
    //////////////////////////////////////////////////End replace by generic function
#endif /* _MMT_BUILD_SDK */
}

void rtp_session_data_cleanup(mmt_session_t * session, unsigned index) {
    if (session->session_data[index] != NULL) {
        mmt_free(session->session_data[index]);
#ifndef _MMT_BUILD_SDK
        //TODO: free the fuzz quality estimation context
        //rtp_session_data->rtp_quality_index_context.quality_index_internal_struct
#endif /* _MMT_BUILD_SDK */
    }
}

int rtp_session_data_analysis(ipacket_t * ipacket, unsigned index) {
    //Dummy function! just calls the function registered with the session context
    struct rtp_session_data_struct * rtp_session_data = ipacket->session->session_data[index];
    rtp_session_data->rtp_data_analysis(ipacket, index);
    return MMT_CONTINUE;
}

static attribute_metadata_t rtp_attributes_metadata[RTP_ATTRIBUTES_NB] = {
    {RTP_VERSION, RTP_VERSION_SHORT_LABEL, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, rtp_version_extraction},

    {RTP_PADDING, RTP_PADDING_SHORT_LABEL, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, rtp_padding_extraction},
    {RTP_EXTENSION, RTP_EXTENSION_SHORT_LABEL, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, rtp_extension_extraction},
    {RTP_CSRCCOUNT, RTP_CSRCCOUNT_SHORT_LABEL, MMT_U8_DATA, sizeof (uint8_t), 0, SCOPE_PACKET, rtp_cc_extraction},
    {RTP_MARKER, RTP_MARKER_SHORT_LABEL, MMT_U8_DATA, sizeof (uint8_t), 1, SCOPE_PACKET, rtp_marker_extraction},
    {RTP_PAYLOADTYPE, RTP_PAYLOADTYPE_SHORT_LABEL, MMT_U8_DATA, sizeof (uint8_t), 1, SCOPE_PACKET, rtp_payload_type_extraction},
    {RTP_SEQNB, RTP_SEQNB_SHORT_LABEL, MMT_U16_DATA, sizeof (uint16_t), 2, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {RTP_TIMESTAMP, RTP_TIMESTAMP_SHORT_LABEL, MMT_U32_DATA, sizeof (uint32_t), 4, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {RTP_SSRC, RTP_SSRC_SHORT_LABEL, MMT_U32_DATA, sizeof (uint32_t), 8, SCOPE_PACKET, general_int_extraction_with_ordering_change},
    {RTP_CSRC, RTP_CSRC_SHORT_LABEL, MMT_BINARY_DATA, BINARY_64DATA_TYPE_LEN, 12, SCOPE_PACKET, rtp_csrc_list_extraction},

    {RTP_QUALITY_INDEX, RTP_QUALITY_INDEX_SHORT_LABEL, MMT_U64_DATA, sizeof (double), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_quality_index_extraction},
    {RTP_JITTER, RTP_JITTER_SHORT_LABEL, MMT_U32_DATA, sizeof (uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_jitter_extraction},
    {RTP_INTER_ARRIVAL_JITTER, RTP_INTER_ARRIVAL_JITTER_SHORT_LABEL, MMT_U32_DATA, sizeof (uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_inter_arrival_jitter_extraction},
    {RTP_INTER_DELAY, RTP_INTER_DELAY_SHORT_LABEL, MMT_U32_DATA, sizeof (uint32_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_inter_delay_extraction},
    {RTP_LOSS, RTP_LOSS_SHORT_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_loss_extraction},
    {RTP_BURST_LOSS, RTP_BURST_LOSS_SHORT_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_burst_loss_extraction},
    {RTP_UNORDER, RTP_UNORDER_SHORT_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_nb_out_of_order_extraction},
    {RTP_DUPLICATE, RTP_DUPLICATE_SHORT_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_duplicate_extraction},
    {RTP_ERROR_ORDER, RTP_ERROR_ORDER_SHORT_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, rtp_order_error_extraction},
};

static void mmt_int_rtp_add_connection(ipacket_t * ipacket) {
    mmt_internal_add_connection(ipacket, PROTO_RTP, MMT_REAL_PROTOCOL);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_id_struct *src = ipacket->internal_packet->src;
    struct mmt_internal_tcpip_id_struct *dst = ipacket->internal_packet->dst;
    /* Check the protocol by the IP addresses!!!*/
    uint32_t proto = get_proto_id_from_address(ipacket);
    if (proto != PROTO_UNKNOWN) {
        switch (proto) {
            case PROTO_GOOGLE:
                mmt_internal_add_connection(ipacket, PROTO_GTALK, MMT_CORRELATED_PROTOCOL);
                return;
            default:
                mmt_internal_add_connection(ipacket, proto, MMT_CORRELATED_PROTOCOL);
                return;
        }
    }else if((proto = check_local_proto_by_port_nb(packet->udp->dest, &dst->local_protos)) != PROTO_UNKNOWN) {
        mmt_internal_add_connection(ipacket, proto, MMT_CORRELATED_PROTOCOL);
        return;
    }else if((proto = check_local_proto_by_port_nb(packet->udp->source, &src->local_protos)) != PROTO_UNKNOWN) {
        mmt_internal_add_connection(ipacket, proto, MMT_CORRELATED_PROTOCOL);
        return;
    } else if ((proto = get_local_conv_proto(ipacket)) != PROTO_UNKNOWN) {
        switch (proto) {
            case PROTO_GOOGLE:
                mmt_internal_add_connection(ipacket, PROTO_GTALK, MMT_CORRELATED_PROTOCOL);
                return;
            case PROTO_APPLE:
                mmt_internal_add_connection(ipacket, PROTO_FACETIME, MMT_CORRELATED_PROTOCOL);
                return;
            case PROTO_YAHOO:
                mmt_internal_add_connection(ipacket, PROTO_YAHOOMSG, MMT_CORRELATED_PROTOCOL);
                return;
            default:
                mmt_internal_add_connection(ipacket, proto, MMT_CORRELATED_PROTOCOL);
                return;
        }
    }
}
/*
 * maintenance of current highest sequence number, cycle count, packet counter
 * adapted from RFC3550 Appendix A.1
 *
 * In their formulation, it is not possible to represent "no packets sent yet". This is fixed here by defining
 * baseseq to be the sequence number of the first packet minus 1 (in other words, the sequence number of the
 * zeroth packet).
 *
 * Note: As described in the RFC, the number of packets received includes retransmitted packets.
 * This means the "packets lost" count (seq_num-isn+1)-received can become negative.
 *
 * include_current_packet should be
 *   1, if the current packet should count towards the total, or
 *   0, if it it regarded as belonging to the previous reporting interval
 */

static void init_seq(struct mmt_internal_tcpip_session_struct *flow, uint8_t direction, uint16_t seq) {
    flow->rtp_seqnum[direction] = seq;
    MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "rtp_seqnum[%u] = %u\n", direction, seq);
}

/* returns difference between old and new highest sequence number */

static uint16_t update_seq(struct mmt_internal_tcpip_session_struct *flow, uint8_t direction, uint16_t seq) {
    uint16_t delta = seq - flow->rtp_seqnum[direction];


    if (delta < RTP_MAX_OUT_OF_ORDER) { /* in order, with permissible gap */
        flow->rtp_seqnum[direction] = seq;
        return delta;
    } else {
        return 0;
    }
}

static void mmt_rtp_search(ipacket_t * ipacket, const uint8_t * payload, const uint16_t payload_len) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;
    uint8_t stage;
    uint16_t seqnum = ntohs(get_u16(payload, 2));

    MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "search rtp.\n");

    if (payload_len == 4 && get_u32(packet->payload, 0) == 0 && ipacket->session->data_packet_count < 8) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "need next packet, maybe ClearSea out calls.\n");
        return;
    }

    if (payload_len == 5 && mmt_memcmp(payload, "hello", 5) == 0) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                "need next packet, initial hello packet of SIP out calls.\n");
        return;
    }

    if (payload_len == 1 && payload[0] == 0) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                "need next packet, payload_packet_len == 1 && payload[0] == 0.\n");
        return;
    }

    if (payload_len == 3 && mmt_memcmp(payload, "png", 3) == 0) {
        /* weird packet found in Ninja GlobalIP trace */
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "skipping packet with len = 3 and png payload.\n");
        return;
    }

    if (payload_len < 12) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "minimal packet size for rtp packets: 12.\n");
        goto exclude_rtp;
    }

    if (payload_len == 12 && get_u32(payload, 0) == 0 && get_u32(payload, 4) == 0 && get_u32(payload, 8) == 0) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "skipping packet with len = 12 and only 0-bytes.\n");
        return;
    }

    if ((payload[0] & 0xc0) == 0xc0 || (payload[0] & 0xc0) == 0x40 || (payload[0] & 0xc0) == 0x00) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "version = 3 || 1 || 0, maybe first rtp packet.\n");
        return;
    }

    if ((payload[0] & 0xc0) != 0x80) {
        MMT_LOG(PROTO_RTP,
                MMT_LOG_DEBUG, "rtp version must be 2, first two bits of a packets must be 10.\n");
        goto exclude_rtp;
    }

    /* rtp_payload_type are the last seven bits of the second byte */
    if (flow->rtp_payload_type[ipacket->session->last_packet_direction] != (payload[1] & 0x7F)) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "payload_type has changed, reset stages.\n");
        ipacket->session->last_packet_direction == 0 ? (flow->rtp_stage1 = 0) : (flow->rtp_stage2 = 0);
    }
    /* first bit of first byte is not part of payload_type */
    flow->rtp_payload_type[ipacket->session->last_packet_direction] = payload[1] & 0x7F;

    stage = (ipacket->session->last_packet_direction == 0 ? flow->rtp_stage1 : flow->rtp_stage2);

    if (stage > 0) {
        MMT_LOG(PROTO_RTP,
                MMT_LOG_DEBUG, "stage = %u.\n", packet->last_packet_direction == 0 ? flow->rtp_stage1 : flow->rtp_stage2);
        if (flow->rtp_ssid[ipacket->session->last_packet_direction] != get_u32(payload, 8)) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "ssid has changed, goto exclude rtp.\n");
            goto exclude_rtp;
        }

        if (seqnum == flow->rtp_seqnum[ipacket->session->last_packet_direction]) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "maybe \"retransmission\", need next packet.\n");
            return;
        } else if ((uint16_t) (seqnum - flow->rtp_seqnum[ipacket->session->last_packet_direction]) < RTP_MAX_OUT_OF_ORDER) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                    "new packet has larger sequence number (within valid range)\n");
            update_seq(flow, ipacket->session->last_packet_direction, seqnum);
        } else if ((uint16_t) (flow->rtp_seqnum[ipacket->session->last_packet_direction] - seqnum) < RTP_MAX_OUT_OF_ORDER) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                    "new packet has smaller sequence number (within valid range)\n");
            init_seq(flow, ipacket->session->last_packet_direction, seqnum);
        } else {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                    "sequence number diff is too big, goto exclude rtp.\n");
            goto exclude_rtp;
        }
    } else {
        MMT_LOG(PROTO_RTP,
                MMT_LOG_DEBUG, "rtp_ssid[%u] = %u.\n", ipacket->session->last_packet_direction,
                flow->rtp_ssid[ipacket->session->last_packet_direction]);
        flow->rtp_ssid[ipacket->session->last_packet_direction] = get_u32(payload, 8);
        if (ipacket->session->data_packet_count < 3) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "packet_counter < 3, need next packet.\n");
        }
        init_seq(flow, ipacket->session->last_packet_direction, seqnum);
    }
    if (seqnum <= 3) {
        MMT_LOG(PROTO_RTP,
                MMT_LOG_DEBUG, "sequence_number = %u, too small, need next packet, return.\n", seqnum);
        return;
    }

    if (stage == 3) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "add connection I.\n");
        mmt_int_rtp_add_connection(ipacket);
    } else {
        ipacket->session->last_packet_direction == 0 ? flow->rtp_stage1++ : flow->rtp_stage2++;
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "stage[%u]++; need next packet.\n",
                ipacket->session->last_packet_direction);
    }
    return;

exclude_rtp:
#ifdef PROTO_STUN
    if (packet->detected_protocol_stack[0] == PROTO_STUN
            || packet->real_protocol_read_only == PROTO_STUN) {
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "STUN: is detected, need next packet.\n");
        return;
    }
#endif							/*  PROTOCOL_STUN */
    MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "exclude rtp.\n");
    MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTP);
}

void mmt_classify_me_rtp(ipacket_t * ipacket, unsigned index) {


    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    if (packet->udp) {
        mmt_rtp_search(ipacket, packet->payload, packet->payload_packet_len);
    } else if (packet->tcp) {

        /* skip special packets seen at yahoo traces */
        if (packet->payload_packet_len >= 20 && ntohs(get_u16(packet->payload, 2)) + 20 == packet->payload_packet_len &&
                packet->payload[0] == 0x90 && packet->payload[1] >= 0x01 && packet->payload[1] <= 0x07) {
            if (ipacket->session->data_packet_count == 2)
                flow->l4.tcp.rtp_special_packets_seen = 1;
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                    "skipping STUN-like, special yahoo packets with payload[0] == 0x90.\n");
            return;
        }
#ifdef PROTO_STUN
        /* TODO the rtp detection sometimes doesn't exclude rtp
         * so for TCP flows only run the detection if STUN has been
         * detected (or RTP is already detected)
         * If flows will be seen which start directly with RTP
         * we can remove this restriction
         */

        if (packet->detected_protocol_stack[0] == PROTO_STUN
                || packet->detected_protocol_stack[0] == PROTO_RTP) {

            /* RTP may be encapsulated in TCP packets */

            if (packet->payload_packet_len >= 2 && ntohs(get_u16(packet->payload, 0)) + 2 == packet->payload_packet_len) {

                /* TODO there could be several RTP packets in a single TCP packet so maybe the detection could be
                 * improved by checking only the RTP packet of given length */

                mmt_rtp_search(ipacket, packet->payload + 2, packet->payload_packet_len - 2);

                return;
            }
        }
        if (flow!=NULL && packet->detected_protocol_stack[0] == PROTO_UNKNOWN && flow->l4.tcp.rtp_special_packets_seen == 1) {

            if (packet->payload_packet_len >= 4 && ntohl(get_u32(packet->payload, 0)) + 4 == packet->payload_packet_len) {

                /* TODO there could be several RTP packets in a single TCP packet so maybe the detection could be
                 * improved by checking only the RTP packet of given length */

                mmt_rtp_search(ipacket, packet->payload + 4, packet->payload_packet_len - 4);

                return;
            }
        }

        if (MMT_FLOW_PROTOCOL_EXCLUDED(flow, PROTO_STUN)) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "exclude rtp.\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTP);
        } else {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "STUN not yet excluded, need next packet.\n");
        }
#else
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "exclude rtp.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTP);
#endif
    }
}

int mmt_check_rtp_udp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {

        mmt_rtp_search(ipacket, packet->payload, packet->payload_packet_len);
    }
    return 4;
}

int mmt_check_rtp_tcp(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if ((selection_bitmask & packet->mmt_selection_packet) == selection_bitmask
            && MMT_BITMASK_COMPARE(excluded_protocol_bitmask, packet->flow->excluded_protocol_bitmask) == 0
            && MMT_BITMASK_COMPARE(detection_bitmask, packet->detection_bitmask) != 0) {


        struct mmt_internal_tcpip_session_struct *flow = packet->flow;

        /* skip special packets seen at yahoo traces */
        if (packet->payload_packet_len >= 20 && ntohs(get_u16(packet->payload, 2)) + 20 == packet->payload_packet_len &&
                packet->payload[0] == 0x90 && packet->payload[1] >= 0x01 && packet->payload[1] <= 0x07) {
            if (ipacket->session->data_packet_count == 2)
                flow->l4.tcp.rtp_special_packets_seen = 1;
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG,
                    "skipping STUN-like, special yahoo packets with payload[0] == 0x90.\n");
            return 4;
        }
#ifdef PROTO_STUN
        /* TODO the rtp detection sometimes doesn't exclude rtp
         * so for TCP flows only run the detection if STUN has been
         * detected (or RTP is already detected)
         * If flows will be seen which start directly with RTP
         * we can remove this restriction
         */

        if (packet->detected_protocol_stack[0] == PROTO_STUN
                || packet->detected_protocol_stack[0] == PROTO_RTP) {

            /* RTP may be encapsulated in TCP packets */
            if (packet->payload_packet_len >= 2 && ntohs(get_u16(packet->payload, 0)) + 2 == packet->payload_packet_len) {
                /* TODO there could be several RTP packets in a single TCP packet so maybe the detection could be
                 * improved by checking only the RTP packet of given length */
                mmt_rtp_search(ipacket, packet->payload + 2, packet->payload_packet_len - 2);
                return 4;
            }
        }
        if (flow != NULL && packet->detected_protocol_stack[0] == PROTO_UNKNOWN && flow->l4.tcp.rtp_special_packets_seen == 1)
        {
            if (packet->payload_packet_len >= 4 && ntohl(get_u32(packet->payload, 0)) + 4 == packet->payload_packet_len) {
                /* TODO there could be several RTP packets in a single TCP packet so maybe the detection could be
                 * improved by checking only the RTP packet of given length */
                mmt_rtp_search(ipacket, packet->payload + 4, packet->payload_packet_len - 4);
                return 4;
            }
        }

        if (MMT_FLOW_PROTOCOL_EXCLUDED(flow, PROTO_STUN)) {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "exclude rtp.\n");
            MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTP);
        } else {
            MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "STUN not yet excluded, need next packet.\n");
        }
#else
        MMT_LOG(PROTO_RTP, MMT_LOG_DEBUG, "exclude rtp.\n");
        MMT_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, PROTO_RTP);
#endif
    }
    return 0;
}

void mmt_init_classify_me_rtp() {
    selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD;
    MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_STUN);
    MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_SIP);
    MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_RTP);
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_rtp_struct() {

    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_RTP, PROTO_RTP_ALIAS);

    if (protocol_struct != NULL) {

        int i = 0;
        for (; i < RTP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &rtp_attributes_metadata[i]);
        }

        mmt_init_classify_me_rtp();

#ifdef _MMT_BUILD_SDK
        register_session_data_initialization_function(protocol_struct, rtp_session_data_init);
        register_session_data_cleanup_function(protocol_struct, rtp_session_data_cleanup);
        register_session_data_analysis_function(protocol_struct, rtp_session_data_analysis);
#endif /* _MMT_BUILD_SDK */

        return register_protocol(protocol_struct, PROTO_RTP);
    } else {
        return 0;
    }

}


