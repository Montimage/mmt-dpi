/*
 * File:   test1.c
 * Author: TM
 *
 * Created on 2 septembre 2011, 11:34
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "mmt_quality_estimation_utilities.h"

application_quality_estimation_internal_t * init_new_internal_application_quality_estimation_struct(application_quality_estimation_t * app_q_est) {
    if (app_q_est != NULL) {
        application_quality_estimation_internal_t * app_q_est_internal = (application_quality_estimation_internal_t *) malloc(sizeof (application_quality_estimation_internal_t));
        if (app_q_est_internal != NULL) {

            app_q_est_internal->application_quality_estimation = app_q_est;

            int nb_metrics = app_q_est->nb_metrics;
            int nb_estimation_metrics = app_q_est->nb_estimation_metrics;

            /* Verification:
             * - nb_metrics must be >= 1
             * - nb_estimation_metrics must be 1 if (QUALITY_ESTIMATION_MODE == SINGLE_QUALITY_METRIC)
             * - nb_estimation_metrics must be >= 1 if (QUALITY_ESTIMATION_MODE == MULTI_QUALITY_METRICS)
             */

            if (nb_metrics <= 0)
                exit(-1);
            if (QUALITY_ESTIMATION_MODE == MULTI_QUALITY_METRICS && nb_estimation_metrics <= 0)
                exit(-1);
            if (QUALITY_ESTIMATION_MODE == SINGLE_QUALITY_METRIC && nb_estimation_metrics != 1)
                exit(-1);


            app_q_est_internal->metric_values = malloc(nb_metrics * sizeof (double *));
            app_q_est_internal->quality_metrics_estimated_values = malloc(nb_estimation_metrics * sizeof (double));
            if (app_q_est_internal->metric_values == NULL || app_q_est_internal->quality_metrics_estimated_values == NULL) {
                exit(-1);
            }

            //Allocating memory for Membership function Array
            app_q_est_internal->metrics_membership_function_values_matrix = malloc(nb_metrics * sizeof (double *));
            if (app_q_est_internal->metrics_membership_function_values_matrix == NULL) {
                exit(-1);
            }
            metric_t * temp_metric = app_q_est->metrics;
            int count = 0;
            while (temp_metric != NULL) {
                app_q_est_internal->metrics_membership_function_values_matrix[count] = malloc(temp_metric->nb_grades * sizeof (double));
                if (app_q_est_internal->metrics_membership_function_values_matrix[count] == NULL) {
                    exit(-1);
                }
                count++;
                temp_metric = temp_metric->next;
            }
        }
        return app_q_est_internal;
    }
    return NULL;
}

/**
 *
 * @param app_id
 * @return
 */
application_quality_estimation_t * init_new_application_quality_estimation_struct(int app_id) {
    application_quality_estimation_t * new_application;
    new_application = (application_quality_estimation_t *) malloc(sizeof (application_quality_estimation_t));
    if (new_application == NULL) {
        fprintf(stderr, "Memory allocation Error while initializing new Application struct! Exiting\n");
        exit(-1);
    }
    memset(new_application, '\0', sizeof (application_quality_estimation_t));
    new_application->app_id = app_id;

    return new_application;
}

application_quality_estimation_rules_t * init_new_app_quality_estimation_rules(int rules_aggregation_type) {
    application_quality_estimation_rules_t * new_app_rules;
    new_app_rules = malloc(sizeof (application_quality_estimation_rules_t));
    if (new_app_rules == NULL) {
        fprintf(stderr, "Memory allocation Error while initializing new Application rules struct! Exiting\n");
        exit(-1);
    }

    memset(new_app_rules, '\0', sizeof (application_quality_estimation_rules_t));
    new_app_rules->aggregation_type = rules_aggregation_type; // for 1 = maximum aggregation and 2= sum aggregation

    return new_app_rules;
}

int register_application_quality_estimation_rule(application_quality_estimation_rules_t * app_rules, rule_t * rule) {
    int retval = 0;
    if (app_rules && rule) {
        rule->next = app_rules->rules;
        app_rules->rules = rule;
        app_rules->nb_rules++;
        retval = 1;
    }

    return retval;
}

rule_t * init_new_rule_struct(int rule_type) {
    rule_t * new_rule = malloc(sizeof (rule_t));
    if (new_rule == NULL) {
        fprintf(stderr, "Memory allocation Error while initializing new Rule struct! Exiting\n");
        exit(-1);
    }

    memset(new_rule, '\0', sizeof (rule_t));
    new_rule->rule_type = rule_type;

    return new_rule;
}

int is_existing_grade_value(metric_t * metric, int grade_value) {
    int retval = 0;
    metric_grade_membership_function_t * grade_membership_function = metric->metric_grades;
    while (grade_membership_function != NULL) {
        if (grade_value == grade_membership_function->grade_value)
            return 1;

        grade_membership_function = grade_membership_function->next;
    }
    return retval;
}

metric_grade_membership_function_t * get_grade_struct(metric_t * metric, int grade_value) {
    metric_grade_membership_function_t * grade_membership_function = metric->metric_grades;
    while (grade_membership_function != NULL) {
        if (grade_value == grade_membership_function->grade_value)
            return grade_membership_function;

        grade_membership_function = grade_membership_function->next;
    }
    return NULL;
}

int is_existing_metric_and_grade(application_quality_estimation_t * application_struct, int metric_id, int grade_value) {
    int retval = 0;
    metric_t * temp_metric = application_struct->metrics;
    while (temp_metric != NULL) {
        if (temp_metric->metric_id == metric_id) {
            if (is_existing_grade_value(temp_metric, grade_value))
                return 1;
        }
        temp_metric = temp_metric->next;
    }
    return retval;
}

/**
 *
 * @param application_struct
 * @param quality_metric_id
 * @param grade_value
 * @return
 */
int is_existing_quality_metric_and_grade(application_quality_estimation_t * application_struct, int quality_metric_id, int grade_value) {
    int retval = 0;
    metric_t * temp_metric = application_struct->estimation_metrics;
    if (QUALITY_ESTIMATION_MODE == MULTI_QUALITY_METRICS) {
        while (temp_metric != NULL) {
            if (temp_metric->metric_id == quality_metric_id) {
                if (is_existing_grade_value(temp_metric, grade_value))
                    return 1;
            }
            temp_metric = temp_metric->next;
        }
    } else if (QUALITY_ESTIMATION_MODE == SINGLE_QUALITY_METRIC) {
        if (temp_metric != NULL) {
            if (temp_metric->metric_id == quality_metric_id) {
                if (is_existing_grade_value(temp_metric, grade_value))
                    return 1;
            }
        }
    }
    return retval;
}

metric_t * get_metric_by_id(application_quality_estimation_t * application_struct, int metric_id) {
    metric_t * temp_metric = application_struct->metrics;
    while (temp_metric != NULL) {
        if (temp_metric->metric_id == metric_id) {
            return temp_metric;
        }
        temp_metric = temp_metric->next;
    }
    return NULL;
}

metric_t * get_quality_metric_by_id(application_quality_estimation_t * application_struct, int quality_metric_id) {
    metric_t * temp_metric = application_struct->estimation_metrics;

    if (QUALITY_ESTIMATION_MODE == MULTI_QUALITY_METRICS) {
        while (temp_metric != NULL) {
            if (temp_metric->metric_id == quality_metric_id) {
                return temp_metric;
            }
            temp_metric = temp_metric->next;
        }
    } else if (QUALITY_ESTIMATION_MODE == SINGLE_QUALITY_METRIC) {
        if (temp_metric != NULL) {
            if (temp_metric->metric_id == quality_metric_id) {
                return temp_metric;
            }
        }
    }
    return NULL;
}

int register_metric_with_grade_to_rule_struct(application_quality_estimation_t * application_struct, rule_t * rule, int metric_id, int grade_value) {
    int retval = 0;
    if (!application_struct || !rule) {
        retval = 0;
    } else if (is_existing_metric_and_grade(application_struct, metric_id, grade_value)) {
        metric_t * metric = get_metric_by_id(application_struct, metric_id);
        metric_grade_membership_function_t * grade = get_grade_struct(metric, grade_value);

        metric_grade_rule_element_t * new_rule_element = malloc(sizeof (metric_grade_rule_element_t));
        if (new_rule_element == NULL) {
            fprintf(stderr, "Memory allocation Error while initializing new Rule Element struct! Exiting\n");
            exit(-1);
        }
        memset(new_rule_element, '\0', sizeof (metric_grade_rule_element_t));
        new_rule_element->metric = metric;
        new_rule_element->metric_grade = grade; //This is the same as grade_value in the function parameters

        //Now we add the rule element in the rule structure
        new_rule_element->next = rule->metric_elements;
        rule->metric_elements = new_rule_element;

        rule->nb_elements++;

        retval = 1;
    }

    return retval;
}

int register_quality_estimation_metric_with_grade_to_rule_struct(application_quality_estimation_t * application_struct, rule_t * rule, int quality_metric_id, int grade_value) {
    int retval = 0;
    if (!application_struct || !rule) {
        retval = 0;
    } else if (is_existing_quality_metric_and_grade(application_struct, quality_metric_id, grade_value)) {
        metric_t * metric = get_quality_metric_by_id(application_struct, quality_metric_id);
        metric_grade_membership_function_t * grade = get_grade_struct(metric, grade_value);

        metric_grade_rule_element_t * new_rule_element = malloc(sizeof (metric_grade_rule_element_t));
        if (new_rule_element == NULL) {
            fprintf(stderr, "Memory allocation Error while initializing new Rule Element struct! Exiting\n");
            exit(-1);
        }
        memset(new_rule_element, '\0', sizeof (metric_grade_rule_element_t));
        new_rule_element->metric = metric;
        new_rule_element->metric_grade = grade; //This is the same as grade_value in the function parameters

        //Now we add the rule element in the rule structure
        new_rule_element->next = rule->quality_metric_elements;
        rule->quality_metric_elements = new_rule_element;

        retval = 1;
    }

    return retval;
}

int register_estimation_rules_with_quality_metric(application_quality_estimation_t * application_struct, application_quality_estimation_rules_t * app_rules, int quality_metric_id) {
    int retval = 0;
    if (!application_struct || !app_rules) {
        retval = 0;
    } else {
        metric_t * quality_metric = get_quality_metric_by_id(application_struct, quality_metric_id);
        if (quality_metric) {
            quality_metric->quality_estimation_rules = app_rules;
            retval = 1;
        }
    }

    return retval;
}

/**
 *
 * @param application
 * @param metric
 * @param metric_type
 * @return
 */
int register_metric_with_application_struct(application_quality_estimation_t * application, metric_t * metric, int metric_type) {
    int retval = 0;
    if (metric_type == QUALITY_INDEX) {
        if (QUALITY_ESTIMATION_MODE == MULTI_QUALITY_METRICS) {
            //We insert the element at the end of the list in order not to disturb the indexes of existing elements
            if (application->estimation_metrics == NULL) {
                metric->next = application->estimation_metrics;
                application->estimation_metrics = metric;
                metric->metric_index = 0;
                application->nb_estimation_metrics = 1; //It was zero before! anyway we set it to 1 to be on the safe side :)
            } else {
                metric_t * temp_metric = application->estimation_metrics;
                //Go to the last element
                while (temp_metric->next != NULL) {
                    temp_metric = temp_metric->next;
                }
                //Insert the new metric at the end of the list
                temp_metric->next = metric;
                //Ensure the metric to register points to null
                metric->next = NULL;
                metric->metric_index = application->nb_estimation_metrics;
                application->nb_estimation_metrics++;
            }
            retval = 1;
        } else if (QUALITY_ESTIMATION_MODE == SINGLE_QUALITY_METRIC) {
            if (application->estimation_metrics == NULL) {
                metric->next = application->estimation_metrics;
                application->estimation_metrics = metric;
                metric->metric_index = 0;
                application->nb_estimation_metrics = 1; //It was zero before! anyway we set it to 1 to be on the safe side :)
                retval = 1;
            }
        }
    } else if (metric_type == METRIC) {
        //We insert the element at the end of the list in order not to disturb the indexes of existing elements
        if (application->metrics == NULL) {
            metric->next = application->metrics;
            application->metrics = metric;
            metric->metric_index = 0;
            application->nb_metrics = 1; //It was zero before! anyway we set it to 1 to be on the safe side :)
        } else {
            metric_t * temp_metric = application->metrics;
            //Go to the last element
            while (temp_metric->next != NULL) {
                temp_metric = temp_metric->next;
            }
            //Insert the new metric at the end of the list
            temp_metric->next = metric;
            //Ensure the metric to register points to null
            metric->next = NULL;
            metric->metric_index = application->nb_metrics;
            application->nb_metrics++;
        }
        retval = 1;
    }
    return retval;
}

/**
 *
 * @param metric_id
 * @return
 */
metric_t * init_new_metric_struct(int metric_id, double range_low, double range_high) {
    metric_t * new_metric = (metric_t *) malloc(sizeof (metric_t));
    if (new_metric == NULL) {
        fprintf(stderr, "Memory allocation Error while initializing new metric struct! Exiting\n");
        exit(-1);
    }

    memset(new_metric, '\0', sizeof (metric_t));

    new_metric->metric_id = metric_id;
    new_metric->metric_range_low = range_low;
    new_metric->metric_range_high = range_high;
    return new_metric;
}

double get_metric_range(metric_t * metric) {
    return metric->metric_range_high - metric->metric_range_low;
}

/**
 *
 * @param metric
 * @param grade_membership_function
 * @return
 */
int register_grade_membership_function_with_metric(metric_t * metric, metric_grade_membership_function_t * grade_membership_function) {
    int retval = 1;
    //We insert the element at the end of the list in order not to disturb the indexes of existing elements
    if (metric->metric_grades == NULL) {
        grade_membership_function->next = metric->metric_grades;
        metric->metric_grades = grade_membership_function;
        grade_membership_function->grade_index = 0;
        metric->nb_grades = 1; //It was zero before! anyway we set it to 1 to be on the safe side :)
    } else {
        metric_grade_membership_function_t * temp_grade = metric->metric_grades;
        //Go to the last element
        while (temp_grade->next != NULL) {
            temp_grade = temp_grade->next;
        }
        //Insert the new grade metric at the end of the list
        temp_grade->next = grade_membership_function;
        //Ensure the grade metric to register points to null
        grade_membership_function->next = NULL;
        grade_membership_function->grade_index = metric->nb_grades;
        metric->nb_grades++;
    }
    return retval;
}

/**
 *
 * @param membership_function_type
 * @param grade_value
 * @param nb_parameters
 * @return
 */
metric_grade_membership_function_t * init_new_grade_membership_function(int membership_function_type, int grade_value, int nb_parameters) {
    metric_grade_membership_function_t * grade_membership_function = (metric_grade_membership_function_t *) malloc(sizeof (metric_grade_membership_function_t) + nb_parameters * sizeof (double));
    if (grade_membership_function == NULL) {
        fprintf(stderr, "Memory allocation Error while initializing new grade_membership_function struct! Exiting\n");
        exit(-1);
    }

    memset(grade_membership_function, '\0', sizeof (sizeof (metric_grade_membership_function_t) + nb_parameters * sizeof (double)));
    grade_membership_function->grade_value = grade_value;
    grade_membership_function->membership_function_type = membership_function_type;
    grade_membership_function->nb_membership_function_parameters = nb_parameters;
    grade_membership_function->membership_function_parameters = (double *) &((char *) grade_membership_function)[sizeof (metric_grade_membership_function_t)];

    return grade_membership_function;
}

/**
 * __
 *   \__
 * param1 is the value at the upper level of the slope and param2 is the distance between the lower and upper levels of the slope
 * @param grade_value
 * @param param1
 * @param param2
 * @return
 */
metric_grade_membership_function_t * init_trapez_left_grade_membership_function(int grade_value, double param1, double param2) {
    metric_grade_membership_function_t * grade_membership_function = init_new_grade_membership_function(MMT_TRAPEZ_LEFT, grade_value, 2);

    *(& grade_membership_function->membership_function_parameters[0]) = param1;
    *(& grade_membership_function->membership_function_parameters[1]) = param2 - param1;

    return grade_membership_function;
}

/**
 *    __
 * __/  
 * param1 is the value at the lower level of the slope and param2 is the distance between the upper and lower levels of the slope
 * @param grade_value
 * @param param1
 * @param param2
 * @return 
 */
metric_grade_membership_function_t * init_trapez_right_grade_membership_function(int grade_value, double param1, double param2) {
    metric_grade_membership_function_t * grade_membership_function = init_new_grade_membership_function(MMT_TRAPEZ_RIGHT, grade_value, 2);

    *(& grade_membership_function->membership_function_parameters[0]) = param2;
    *(& grade_membership_function->membership_function_parameters[1]) = param2 - param1;

    return grade_membership_function;
}

/**
 *    ___
 * __/   \__
 * The trapez center is compozed of a trapez right followed by a trapez left
 * param1 and param3 are the parameters of the trapez right part
 * while param2 and param4 are the parameters of the trapez left part.
 * @param grade_value
 * @param param1
 * @param param2
 * @param param3
 * @param param4
 * @return
 */
metric_grade_membership_function_t * init_trapez_center_grade_membership_function(int grade_value, double param1, double param2, double param3, double param4) {
    metric_grade_membership_function_t * grade_membership_function = init_new_grade_membership_function(MMT_TRAPEZ_CENTER, grade_value, 4);

    *(& grade_membership_function->membership_function_parameters[0]) = param2;
    *(& grade_membership_function->membership_function_parameters[1]) = param3;
    *(& grade_membership_function->membership_function_parameters[2]) = param2 - param1;
    *(& grade_membership_function->membership_function_parameters[3]) = param4 - param3;

    return grade_membership_function;
}

/*
 This function returns a membership function acording to membership function type
 */

generic_membership_function_by_kpi_and_grade get_function_by_type(int mfb_function_type)
{
    switch( mfb_function_type ) {
        case 1: return trapezoid_left;
        case 2: return trapezoid_medium;
        case 3: return trapezoid_right;
        case 4: return guassian_left;
        case 5: return guassian_medium;
        case 6: return guassian_right;

        default:
            ;
    }

    return trapezoid_left;
}

/*
 This function returns a membership function value acording to membership function type
 for a particular kpi value
 */
double trapezoid_left(double kpi_value, metric_grade_membership_function_t * mfp_parameters) {

    double membershipvalue;
    //a = parameter 0,beta = parameter 1

    //if (kpi_value <= mfp_parameters->membership_function_parameters[0] && kpi_value >= 0) { //TODO: why kpi_value >=0
    if (kpi_value <= mfp_parameters->membership_function_parameters[0]) {
        membershipvalue = 1;
    } else if ((kpi_value >= mfp_parameters->membership_function_parameters[0]) && kpi_value <= (mfp_parameters->membership_function_parameters[0] + mfp_parameters->membership_function_parameters[1])) {
        membershipvalue = 1 - ((kpi_value - mfp_parameters->membership_function_parameters[0]) / mfp_parameters->membership_function_parameters[1]);
    } else membershipvalue = 0;

    return membershipvalue;
}

double trapezoid_medium(double kpi_value, metric_grade_membership_function_t * mfp_parameters) {
    //a=parameter0,b=parameter1,alpha=parameter2,beta=parameter3
    double membershipvalue;

    if (kpi_value >= (mfp_parameters->membership_function_parameters[0] - mfp_parameters->membership_function_parameters[2]) && kpi_value <= mfp_parameters->membership_function_parameters[0]) {
        membershipvalue = 1 - ((mfp_parameters->membership_function_parameters[0] - kpi_value) / mfp_parameters->membership_function_parameters[2]);
    } else if (kpi_value >= mfp_parameters->membership_function_parameters[0] && kpi_value <= mfp_parameters->membership_function_parameters[1])
        membershipvalue = 1;
    else if (kpi_value >= mfp_parameters->membership_function_parameters[1] && kpi_value <= (mfp_parameters->membership_function_parameters[1] + mfp_parameters->membership_function_parameters[3])) {
        membershipvalue = 1 - ((kpi_value - mfp_parameters->membership_function_parameters[1]) / mfp_parameters->membership_function_parameters[3]);
    } else membershipvalue = 0;

    return membershipvalue;


}

double trapezoid_right(double kpi_value, metric_grade_membership_function_t * mfp_parameters) {
    //a= parameter0;alpha =parameter1

    double membershipvalue;
    if (kpi_value >= mfp_parameters->membership_function_parameters[0]) {
        membershipvalue = 1;
    } else if (kpi_value >= (mfp_parameters->membership_function_parameters[0] - mfp_parameters->membership_function_parameters[1]) && kpi_value <= mfp_parameters->membership_function_parameters[0]) {
        membershipvalue = 1 - ((mfp_parameters->membership_function_parameters[0] - kpi_value) / mfp_parameters->membership_function_parameters[1]);
    } else membershipvalue = 0;

    return membershipvalue;
}
//Observation: isn't there any library that makes this calculation?

double guassian_left(double kpi_value, metric_grade_membership_function_t * mfp_parameters) {
    //mean= parameter0; varience=parameter1

    double membershipvalue;
    membershipvalue = (1 / sqrt(2 * M_PI * pow(mfp_parameters->membership_function_parameters[1], 2))) * exp(-(pow(kpi_value - mfp_parameters->membership_function_parameters[0], 2) / (2 * pow(mfp_parameters->membership_function_parameters[1], 2))));

    return membershipvalue;
}

double guassian_medium(double kpi_value, metric_grade_membership_function_t * mfp_parameters) {
    //mean= parameter0; varience=parameter1
    double membershipvalue;

    membershipvalue = (1 / sqrt(2 * M_PI * pow(mfp_parameters->membership_function_parameters[1], 2)))* (exp(-(pow(kpi_value - mfp_parameters->membership_function_parameters[0], 2) / (2 * pow(mfp_parameters->membership_function_parameters[1], 2)))));



    return membershipvalue;
}

double guassian_right(double kpi_value, metric_grade_membership_function_t * mfp_parameters) {
    //mean= parameter0; varience=parameter1
    double membershipvalue;

    membershipvalue = (1 / sqrt(2 * M_PI * pow(mfp_parameters->membership_function_parameters[1], 2))) * exp(-(pow(kpi_value - mfp_parameters->membership_function_parameters[0], 2) / (2 * pow(mfp_parameters->membership_function_parameters[1], 2))));


    return membershipvalue;
}

/*
 This function returns a rule function acording to rule type
 */

double get_min(double val1, double val2) {
    return MMT_MIN(val1, val2);
}

double get_max(double val1, double val2) {
    return MMT_MAX(val1, val2);
}

generic_rule_function get_rule_function_by_rule_type(int rule_type)
{
    switch( rule_type ) {
        case AND_RULE_TYPE: return (generic_rule_function)get_min;
        case OR_RULE_TYPE:  return (generic_rule_function)get_max;

        default:
            ;
    }

    return (generic_rule_function)get_max;
}

/*
 This function returns a rule index value  acording to rule type.Initially
 the value of p_index is zero/one (AND/OR) and  it is ANDed with rule element
 of a particular rule. p_index is updated each time with new rule element.

 */

/*
 This function compares each rule index array eleent with the current aggragation index element
 to get a updated aggregation index value.
 */
void maximum_aggregation(double * rule_index_array, double * aggregation_index, int sample_nb) {
    int s;

    for (s = 0; s < sample_nb; s++) {
        if (rule_index_array[s] > aggregation_index[s])
            aggregation_index[s] = rule_index_array[s];
    }
}

/*
 This function adds each rule index array element with the current aggragation index element
 to get a updated aggregation index value.
 */


void sum_aggregation(double * rule_index_array, double * aggregation_index, int sample_nb) {
    int s;

    for (s = 0; s < sample_nb; s++) {
        aggregation_index[s] = aggregation_index[s] + rule_index_array[s];
    }
}

/*
 This function returns a aggregation function acording to aggregation type
 */
generic_aggregation_index_array get_aggregation_function(int aggregation_type)
{
    switch( aggregation_type ) {
        case 1: return maximum_aggregation;
        case 2: return sum_aggregation;

        default:
            ;
    }

    return maximum_aggregation;
}
