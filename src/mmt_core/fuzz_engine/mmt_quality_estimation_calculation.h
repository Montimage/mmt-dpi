/* 
 * File:   mmt_quality_estimation_calculation.h
 * Author: montimage
 *
 * Created on 24 novembre 2011, 15:44
 */

#ifndef MMT_QUALITY_ESTIMATION_CALCULATION_H
#define	MMT_QUALITY_ESTIMATION_CALCULATION_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "mmt_quality_estimation_defs.h"
    /*
     Defines the aggregation index array for calculating quality index
     * @param application attributes like rules,MFV, membership function attributes and the kpi corresponding to the application from MMT
     * @return a pointer to the aggregation index array.
     */
    void get_index_value(application_quality_estimation_internal_t * app_internal_struct, metric_t * quality_metric, double * aggregation_index);
    /*
        This function defines a rule function according to rule function type.
     * @param rule function type identifier
     * @return rule function corresponding to that type
     */

    generic_rule_function get_rule_function_by_rule_type(int rule_type);

    /*
        This function defines a individual rule index aray .
     * @param index value, rules and kpi values and sample number for the array.
     * @return rule index array of corresponding individual rule.
     */
    void calculate_index_array(metric_grade_rule_element_t * output_element,
        double index_value, int sample_nb, double * rule_index_array);


    /*
        This function defines aggregation function according to aggregation function type.
     * @param rule aggregation type identifier
     * @return rule aggregation function corresponding to that aggregation type
     */

    generic_aggregation_index_array get_aggregation_function(int aggregation_type);
    /*
        This function defines a quality index corresponding to application.
     * @param aggregation index array and sample number for the array.
     * @return a single quality index value of corresponding application.
     */

    double estimate_quality_index(application_quality_estimation_internal_t * app_internal_struct);

    
    double dummy_quality_index_estimation(application_quality_estimation_internal_t * app_internal_struct);
     /*
    This function should give membership value corresponding to KPI and its corresponding grades according to the function type .
     * @param membership function parameters of particular kpi grade from voip structure and KPI values from MMT
     */

    void set_metric_grades_values_matrix(application_quality_estimation_internal_t * app_internal_struct);

#ifdef	__cplusplus
}
#endif

#endif	/* MMT_QUALITY_ESTIMATION_CALCULATION_H */

