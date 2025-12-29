/*
 * File:   mmt_quality_estimation_utilities.h
 * Author: montimage
 *
 * Created on 24 novembre 2011, 15:47
 */

#ifndef MMT_QUALITY_ESTIMATION_UTILITIES_H
#define MMT_QUALITY_ESTIMATION_UTILITIES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "mmt_quality_estimation_defs.h"

application_quality_estimation_t *application_quality_estimation_xml_parser(char *docname);

application_quality_estimation_t *init_new_application_quality_estimation_struct(int app_id);

application_quality_estimation_internal_t *init_new_internal_application_quality_estimation_struct(
	application_quality_estimation_t *app_q_est);

metric_t *init_new_metric_struct(int metric_id, double range_low, double range_high);

application_quality_estimation_rules_t *init_new_app_quality_estimation_rules(int rules_aggregation_type);

rule_t *init_new_rule_struct(int rule_type);

metric_grade_membership_function_t *init_trapez_left_grade_membership_function(int grade_value, double param1,
																			   double param2);

metric_grade_membership_function_t *init_trapez_right_grade_membership_function(int grade_value, double param1,
																				double param2);

metric_grade_membership_function_t *init_trapez_center_grade_membership_function(int grade_value, double param1,
																				 double param2, double param3,
																				 double param4);

int register_grade_membership_function_with_metric(metric_t *metric,
												   metric_grade_membership_function_t *grade_membership_function);

int register_metric_with_application_struct(application_quality_estimation_t *application, metric_t *metric,
											int metric_type);

int register_application_quality_estimation_rule(application_quality_estimation_rules_t *app_rules, rule_t *rule);

int register_metric_with_grade_to_rule_struct(application_quality_estimation_t *application_struct, rule_t *rule,
											  int metric_id, int grade_value);

int register_quality_estimation_metric_with_grade_to_rule_struct(application_quality_estimation_t *application_struct,
																 rule_t *rule, int quality_metric_id, int grade_value);

int register_estimation_rules_with_quality_metric(application_quality_estimation_t *application_struct,
												  application_quality_estimation_rules_t *app_rules,
												  int quality_metric_id);


metric_t *get_metric_by_id(application_quality_estimation_t *application_struct, int metric_id);

metric_grade_membership_function_t *get_grade_struct(metric_t *metric, int grade_value);

metric_t *get_quality_metric_by_id(application_quality_estimation_t *application_struct, int quality_metric_id);


int is_existing_grade_value(metric_t *metric, int grade_value);

int is_existing_metric_and_grade(application_quality_estimation_t *application_struct, int metric_id, int grade_value);

int is_existing_quality_metric_and_grade(application_quality_estimation_t *application_struct, int quality_metric_id,
										 int grade_value);


double get_metric_range(metric_t *metric);

/*
This function should return a membership function according to membership function type.
 * @param membership function type identifier
 * @return membership function corresponding to that type
 */

generic_membership_function_by_kpi_and_grade get_function_by_type(int mfb_function_type);

/*
This function should give membership value corresponding to KPI and its corresponding grades.
 * @param membership function parameters and KPI values from MMT
 * @return membership function value corresponding to that KPI and grade
 */


/*
This function should give membership value corresponding to KPI and its corresponding grades according to the function
type .
 * @param membership function parameters and KPI values from MMT
 * @return membership function value corresponding to that KPI and grade for the following type
 */

double trapezoid_left(double kpi_value, metric_grade_membership_function_t *mfp_parameters);
double trapezoid_right(double kpi_value, metric_grade_membership_function_t *mfp_parameters);
double trapezoid_medium(double kpi_value, metric_grade_membership_function_t *mfp_parameters);
double guassian_left(double kpi_value, metric_grade_membership_function_t *mfp_parameters);
double guassian_right(double kpi_value, metric_grade_membership_function_t *mfp_parameters);
double guassian_medium(double kpi_value, metric_grade_membership_function_t *mfp_parameters);

metric_t *get_quality_metric_by_id(application_quality_estimation_t *application_struct, int quality_metric_id);


#ifdef __cplusplus
}
#endif

#endif /* MMT_QUALITY_ESTIMATION_UTILITIES_H */
