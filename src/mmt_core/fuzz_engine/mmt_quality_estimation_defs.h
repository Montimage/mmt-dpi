/*
 * File:   mmt_quality_estimation_defs.h
 * Author: montimage
 *
 * Created on 21 novembre 2011, 15:42
 */

#ifndef MMT_QUALITY_ESTIMATION_DEFS_H
#define MMT_QUALITY_ESTIMATION_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#define VoIP 1

#define SINGLE_QUALITY_METRIC 1
#define MULTI_QUALITY_METRICS 2

#define QUALITY_ESTIMATION_MODE SINGLE_QUALITY_METRIC

#define METRIC 1
#define QUALITY_INDEX 2

#define MAX_AGGREGATION 1
#define SUM_AGGREGATION 2

#define AND_RULE 1
#define OR_RULE 2

#define AND_RULE_TYPE 1
#define OR_RULE_TYPE 2

#define SAMPLES_NB 1000

#define MMT_MIN(val1, val2) ((val1 < val2) ? val1 : val2)
#define MMT_MAX(val1, val2) ((val1 > val2) ? val1 : val2)

typedef struct application_quality_estimation_rules_struct application_quality_estimation_rules_t;

enum {
	MMT_TRAPEZ_LEFT = 1, /**< Trapeze left function has 2 parameters:  _
						  *                                             \_ */
	MMT_TRAPEZ_CENTER,   /**< Trapez center has four parameters: _
															   _/ \_ */
	MMT_TRAPEZ_RIGHT,    /**< Trapeze right function has 2 parameters:    __
																	   __/    */
};

/*
Defines a memberfunction type and parameters needed to have  membershipfunction.
Membershipfunction can be trapezoidal_left, trapezoidal_right, guassian_right etc
and to have these function we need some parameters for example mean and variance for
guassian. Each membership function have a type_id as an indentifier.
 */
typedef struct metric_grade_membership_function_struct {
	int grade_index;
	int grade_value;
	char *grade_name;
	int membership_function_type;
	int nb_membership_function_parameters;
	double *membership_function_parameters;
	struct metric_grade_membership_function_struct *next;

} metric_grade_membership_function_t;


/*
Defines a Key Performence Indicator (KPI) and grades for KPI. KPIs can be delay,
jitter etc and is represented by  KPI_id as an indentifier. Grades given for
an KPI can de high,low etc and nb_grades defines number of grades given to a KPI.
 */

typedef struct metric_struct {
	int metric_index;
	int metric_id;
	char *metric_name;
	int nb_grades;

	double metric_range_low;
	double metric_range_high;

	metric_grade_membership_function_t *metric_grades;
	struct application_quality_estimation_rules_struct *quality_estimation_rules;
	struct metric_struct *next;
} metric_t;


/* Defines the elements of the rule structure  */
typedef struct metric_grade_rule_element_struct {
	metric_t *metric;
	metric_grade_membership_function_t *metric_grade;
	struct metric_grade_rule_element_struct *next;
} metric_grade_rule_element_t;

typedef struct rule_struct {
	int rule_type;  // AND or OR rule
	int nb_elements;
	metric_grade_rule_element_t *metric_elements;
	metric_grade_rule_element_t *quality_metric_elements;
	struct rule_struct *next;
} rule_t;

/* Defines rules associated with the particular application, aggregation type
with its maximum or sum etc and number of samples to be included in QOS index
calculation.
 */
struct application_quality_estimation_rules_struct {
	int nb_rules;
	int aggregation_type;
	rule_t *rules;
	// rule_t * q_indexs;

	// int samples_nb;
};
// # define pi 22/7 // isn't pi defined in standard C ??? if yes why redefine it?

/*
Defines the Application and KPI needed for that application. Application can
be VOIP,IPTV etc which is represented by APP_id and the number of KPIs need to
for that application is given by nb_KPI.
 */

typedef struct application_quality_estimation_struct {
	int app_id;
	int nb_metrics;
	int nb_estimation_metrics;
	metric_t *metrics;
	metric_t *estimation_metrics;
	// struct application_quality_estimation_rules_struct * quality_estimation_rules;
} application_quality_estimation_t;

typedef struct application_quality_estimation_internal_struct {
	application_quality_estimation_t *application_quality_estimation;
	double **metric_values;
	double **metrics_membership_function_values_matrix;
	double *quality_metrics_estimated_values;
} application_quality_estimation_internal_t;

typedef double (*generic_membership_function_by_kpi_and_grade)(double kpi_value,
															   metric_grade_membership_function_t *mfp_parameters);

/*
Defines the rules with elements of rule and rule type whether it is AND or
OR operation
 */
typedef double (*generic_rule_function)(double val1, double val2);

typedef void (*generic_aggregation_index_array)(double *index_array, double *aggregation_index, int sample_nb);

typedef double (*generic_session_quality_index_estimation_function)(
	application_quality_estimation_internal_t *app_internal_struct);

application_quality_estimation_t *init_application_quality_estimation_structures(char *model);

#ifdef __cplusplus
}
#endif

#endif /* MMT_QUALITY_ESTIMATION_DEFS_H */
