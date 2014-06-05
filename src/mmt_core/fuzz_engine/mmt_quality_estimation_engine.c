#include "mmt_quality_estimation_defs.h"
#include "mmt_quality_estimation_utilities.h"
#include "packet_processing.h"

application_quality_estimation_t * init_voip_quality_estimation_struct() {
    application_quality_estimation_t * application = NULL;
    metric_t * voip_loss, * voip_jitter, * voip_index;

    application = init_new_application_quality_estimation_struct(VoIP);

    //initialize loss metric
    voip_loss = init_new_metric_struct(12, 0.0, 100.0); //TODO: just a test the metric ID should be defined
    register_grade_membership_function_with_metric(voip_loss, init_trapez_right_grade_membership_function(3, 2, 5));
    register_grade_membership_function_with_metric(voip_loss, init_trapez_center_grade_membership_function(2, 0.5, 2.0, 2.0, 5));
    register_grade_membership_function_with_metric(voip_loss, init_trapez_left_grade_membership_function(1, 0.5, 1));

    //initialize jitter metric
    voip_jitter = init_new_metric_struct(15, 0.0, 100); //TODO: just a test the metric ID should be defined
    register_grade_membership_function_with_metric(voip_jitter, init_trapez_right_grade_membership_function(3, 5, 20));
    register_grade_membership_function_with_metric(voip_jitter, init_trapez_center_grade_membership_function(2, 2, 5, 5, 20));
    register_grade_membership_function_with_metric(voip_jitter, init_trapez_left_grade_membership_function(1, 2, 5));

    //initialize quality index evaluation metric
    voip_index = init_new_metric_struct(3, 1.0, 5.0); //TODO: just a test the metric ID should be defined
    register_grade_membership_function_with_metric(voip_index, init_trapez_left_grade_membership_function(5, 2, 2.5));
    register_grade_membership_function_with_metric(voip_index, init_trapez_center_grade_membership_function(4, 2, 2.5, 2.5, 3));
    register_grade_membership_function_with_metric(voip_index, init_trapez_center_grade_membership_function(3, 2.5, 3, 3, 3.5));
    register_grade_membership_function_with_metric(voip_index, init_trapez_center_grade_membership_function(2, 3, 3.5, 3.5, 4));
    register_grade_membership_function_with_metric(voip_index, init_trapez_right_grade_membership_function(1, 3.5, 4));

    //Now register these metrics
    register_metric_with_application_struct(application, voip_jitter, METRIC);
    register_metric_with_application_struct(application, voip_loss, METRIC);

    //Register the quality index evaluation metric
    register_metric_with_application_struct(application, voip_index, QUALITY_INDEX);


    //Now comes the application rules
    struct application_quality_estimation_rules_struct * quality_estimation_rules = init_new_app_quality_estimation_rules(SUM_AGGREGATION);

    //We have 5 rules
    rule_t * rule1, * rule2, * rule3, * rule4, * rule5, *rule6, *rule7, *rule8, *rule9;
    rule1 = init_new_rule_struct(AND_RULE);
    //New we register the metric/grade elements in the rules


    rule2 = init_new_rule_struct(AND_RULE);
    rule3 = init_new_rule_struct(AND_RULE);
    rule4 = init_new_rule_struct(AND_RULE);
    rule5 = init_new_rule_struct(AND_RULE);
    rule6 = init_new_rule_struct(AND_RULE);
    rule7 = init_new_rule_struct(AND_RULE);
    rule8 = init_new_rule_struct(AND_RULE);
    rule9 = init_new_rule_struct(AND_RULE);

    register_metric_with_grade_to_rule_struct(application, rule1, 15, 1);
    register_metric_with_grade_to_rule_struct(application, rule1, 12, 1);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule1, 3, 1);

    register_metric_with_grade_to_rule_struct(application, rule2, 15, 1);
    register_metric_with_grade_to_rule_struct(application, rule2, 12, 2);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule2, 3, 2);

    register_metric_with_grade_to_rule_struct(application, rule3, 15, 2);
    register_metric_with_grade_to_rule_struct(application, rule3, 12, 1);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule3, 3, 2);

    register_metric_with_grade_to_rule_struct(application, rule4, 15, 2);
    register_metric_with_grade_to_rule_struct(application, rule4, 12, 2);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule4, 3, 3);

    register_metric_with_grade_to_rule_struct(application, rule5, 15, 1);
    register_metric_with_grade_to_rule_struct(application, rule5, 12, 3);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule5, 3, 4);

    register_metric_with_grade_to_rule_struct(application, rule6, 15, 3);
    register_metric_with_grade_to_rule_struct(application, rule6, 12, 1);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule6, 3, 4);

    register_metric_with_grade_to_rule_struct(application, rule7, 15, 3);
    register_metric_with_grade_to_rule_struct(application, rule7, 12, 3);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule7, 3, 5);

    register_metric_with_grade_to_rule_struct(application, rule8, 15, 3);
    register_metric_with_grade_to_rule_struct(application, rule8, 12, 2);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule8, 3, 5);

    register_metric_with_grade_to_rule_struct(application, rule9, 15, 2);
    register_metric_with_grade_to_rule_struct(application, rule9, 12, 3);
    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule9, 3, 5);

    register_application_quality_estimation_rule(quality_estimation_rules, rule1);
    register_application_quality_estimation_rule(quality_estimation_rules, rule5);
    register_application_quality_estimation_rule(quality_estimation_rules, rule2);
    register_application_quality_estimation_rule(quality_estimation_rules, rule3);
    register_application_quality_estimation_rule(quality_estimation_rules, rule4);
    register_application_quality_estimation_rule(quality_estimation_rules, rule6);
    register_application_quality_estimation_rule(quality_estimation_rules, rule7);
    register_application_quality_estimation_rule(quality_estimation_rules, rule8);
    register_application_quality_estimation_rule(quality_estimation_rules, rule9);

    register_estimation_rules_with_quality_metric(application, quality_estimation_rules, 3);

    return application;
}

application_quality_estimation_t * init_application_quality_estimation_structures(char * model) {
    application_quality_estimation_t * new_struct = application_quality_estimation_xml_parser(model);
    return new_struct;
}


