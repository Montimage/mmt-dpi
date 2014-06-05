#include <stdio.h>
#include <stdlib.h>
#include "mmt_quality_estimation_calculation.h"
#include "mmt_quality_estimation_utilities.h"

void set_metric_grades_values_matrix(application_quality_estimation_internal_t * app_internal_struct) {
    double ** metric_values_array = app_internal_struct->metric_values;
    double ** metric_grades_values_matrix = app_internal_struct->metrics_membership_function_values_matrix;
    metric_t * metric = app_internal_struct->application_quality_estimation->metrics;

    /*
     Each application  can have number of kpis so this while loop iterates through Kpis unless its NULL
     so if the application has 2 kpis the loop iterates 2 times
     */
    while (metric != NULL) {
        metric_grade_membership_function_t * metric_grade = metric->metric_grades;

        /*
        Each kpi  can have number of grades so this while loop iterates through grades unless its NULL
        so if the application has 3 grades the loop iterates 3 times
         */
        while (metric_grade != NULL) {
            metric_grades_values_matrix[metric->metric_index][metric_grade->grade_index] =
                    get_function_by_type(metric_grade->membership_function_type)(* metric_values_array[metric->metric_index], metric_grade);

            metric_grade = metric_grade->next;
        }
        metric = metric->next;
    }
}


/*
 This function evaluates each rules of the fuzzy logic to get rule index array and 
 calculates the aggregation index according to aggregation type.
 * Rule index array is the array that represents the result from the each rule. 
 * Aggregation index array is the array that represents the result calculated from each rule index array.
 */

void get_index_value(application_quality_estimation_internal_t * app_internal_struct, metric_t * quality_metric, double * aggregation_index) {
    double index_value;
    double rule_index_array[SAMPLES_NB] = {0};

    rule_t * rule = quality_metric->quality_estimation_rules->rules;

    while (rule != NULL) {
        metric_grade_rule_element_t * rule_element = rule->metric_elements;
        metric_grade_rule_element_t * output_element = rule->quality_metric_elements;

        index_value = app_internal_struct->metrics_membership_function_values_matrix [rule_element->metric->metric_index][rule_element->metric_grade->grade_index];

        while (rule_element != NULL) {
            index_value = get_rule_function_by_rule_type(rule->rule_type)(
                    app_internal_struct->metrics_membership_function_values_matrix [rule_element->metric->metric_index][rule_element->metric_grade->grade_index],
                    index_value);

            rule_element = rule_element->next;
        }

        calculate_index_array(output_element, index_value, SAMPLES_NB, rule_index_array);

        get_aggregation_function(quality_metric->quality_estimation_rules->aggregation_type)(rule_index_array, aggregation_index, SAMPLES_NB);

        rule = rule->next;
    }
}

/*
 This function evaluates each rules of the fuzzy logic to get rule index array,
 the rule index array is calculated for each rule. It contains the sample values 
 of each rule quality index with a quality index membership function.
 */
void calculate_index_array(metric_grade_rule_element_t * output_element,
        double index_value, int sample_nb, double * rule_index_array) {

    int step_nb;
    double x, value, step;

    metric_t * quality_metric = output_element->metric;
    metric_grade_membership_function_t * quality_metric_grade = output_element->metric_grade;

    step = (quality_metric->metric_range_high - quality_metric->metric_range_low) / sample_nb;

    for (step_nb = 0; step_nb <= sample_nb; step_nb++) {
        x = quality_metric->metric_range_low + step_nb*step;

        value = (get_function_by_type(quality_metric_grade->membership_function_type)(x, quality_metric_grade)) * index_value;

        if (value <= index_value) {
            rule_index_array[step_nb] = value;
        } else (rule_index_array[step_nb] = index_value);
    }
}

/*
 This function calculates the centroid (quality index) from a aggregation index array.
 */

double estimate_quality_index(application_quality_estimation_internal_t * app_internal_struct) {

    double centroid;
    int s;
    double sum1 = 0;
    double sum2 = 0;
    double quality_metric_step;
    double input_value;


    quality_metric_step = (app_internal_struct->application_quality_estimation->estimation_metrics->metric_range_high -
            app_internal_struct->application_quality_estimation->estimation_metrics->metric_range_low) / SAMPLES_NB;

    double aggregation_index_array[SAMPLES_NB] = {0};

    set_metric_grades_values_matrix(app_internal_struct);

    get_index_value(app_internal_struct, app_internal_struct->application_quality_estimation->estimation_metrics, aggregation_index_array);
    for (s = 0; s <= SAMPLES_NB; s++) {
        input_value = app_internal_struct->application_quality_estimation->estimation_metrics->metric_range_low + s*quality_metric_step;
        sum1 = sum1 + (aggregation_index_array[s]*(input_value));
        sum2 = sum2 + aggregation_index_array[s];
    }

    if (sum1 == .0)
        centroid = 0.5;
    else
        centroid = sum1 / sum2;

    *app_internal_struct->quality_metrics_estimated_values = centroid;
    return centroid;
}

double dummy_quality_index_estimation(application_quality_estimation_internal_t * app_internal_struct) {
    return 0.0;
}