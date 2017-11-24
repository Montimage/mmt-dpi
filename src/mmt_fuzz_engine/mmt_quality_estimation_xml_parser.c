#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mmt_quality_estimation_calculation.h"
#include "mmt_quality_estimation_utilities.h"

#include <libxml/xmlreader.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>
#include <libxml/encoding.h>
#include <libxml/xmlstring.h>

void die(char *msg) {
    printf("%s", msg);

    return;
}

/*void parseNodekpiparameter(xmlNodePtr cur, int grade_value,int membership_function_type, metric_t * metric, application_quality_estimation_t * application) {

    cur = cur->xmlChildrenNode;
    double  membership_function_parameters[3] ;
    int i = 0;
    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "membership_function_parameters") == 0) {
            (membership_function_parameters[i]) = atof((const char *) cur->children->content);
                       i++;
        }
        cur = cur->next;
    }
    if (membership_function_type == MMT_TRAPEZ_RIGHT)
        register_grade_membership_function_with_metric(metric, init_trapez_right_grade_membership_function(grade_value, membership_function_parameters[0], membership_function_parameters[1]));
    else if (membership_function_type == MMT_TRAPEZ_CENTER)
        register_grade_membership_function_with_metric(metric, init_trapez_center_grade_membership_function(grade_value, membership_function_parameters[0], membership_function_parameters[1],membership_function_parameters[2], membership_function_parameters[3]));
    if (membership_function_type == MMT_TRAPEZ_LEFT)
        register_grade_membership_function_with_metric(metric, init_trapez_left_grade_membership_function(grade_value, membership_function_parameters[0], membership_function_parameters[1]));

    return;
}*/

void parseNodeparameter(xmlNodePtr cur,int grade_value,int membership_function_type, metric_t * metric) {

    cur = cur->xmlChildrenNode;
  double  membership_function_parameters[4];
    int i = 0;
    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "membership_function_parameters") == 0) {
            (membership_function_parameters[i]) = atof((const char *) cur->children->content);
                        i++;
        }
        cur = cur->next;
    }
    if (membership_function_type == MMT_TRAPEZ_RIGHT)
        register_grade_membership_function_with_metric(metric, init_trapez_right_grade_membership_function(grade_value, membership_function_parameters[0], membership_function_parameters[1]));
    else if (membership_function_type == MMT_TRAPEZ_CENTER)
        register_grade_membership_function_with_metric(metric, init_trapez_center_grade_membership_function(grade_value, membership_function_parameters[0], membership_function_parameters[1],membership_function_parameters[2], membership_function_parameters[3]));
    else if (membership_function_type == MMT_TRAPEZ_LEFT)
        register_grade_membership_function_with_metric(metric, init_trapez_left_grade_membership_function(grade_value, membership_function_parameters[0], membership_function_parameters[1]));


    return;
}
/*void parseNodekpigrade(xmlNodePtr cur, metric_t * metric, application_quality_estimation_t * application) {


    int grade_value, grade_index,membership_function_type,nb_membership_function_parameters;
    char grade_name[20];
    xmlAttr *attr_node2 = NULL;



    if (xmlStrcmp(cur->name, (const xmlChar *) "grade") == 0) {
        for (attr_node2 = cur->properties; attr_node2; attr_node2 = attr_node2->next) {
            if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_index") == 0) {
                grade_index = atoi((const char *) attr_node2->children->content);

            } else if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_name") == 0) {
                strncpy(grade_name, attr_node2->children->content, 20);

            } else if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_value") == 0) {
                grade_value = atoi((const char *) attr_node2->children->content);

            }
        }
    }


    cur = cur->xmlChildrenNode;

    while (cur != NULL) {

        if (xmlStrcmp(cur->name, (const xmlChar *) "membership_function_type") == 0) {
            membership_function_type = atoi((const char *) cur->children->content);

        } else if (xmlStrcmp(cur->name, (const xmlChar *) "nb_membership_function_parameters") == 0) {
            nb_membership_function_parameters = atoi((const char *) cur->children->content);

        } else if (xmlStrcmp(cur->name, (const xmlChar *) "parameters") == 0)

            parseNodeparameter(cur, grade_value,membership_function_type, metric, application);

        cur = cur->next;


    }
    return;
}
*/

void parseNodegrade(xmlNodePtr cur, metric_t * metric_index) {

    xmlAttr *attr_node2 = NULL;
     int grade_value = 0, membership_function_type = 0;
     /* Those are set, but not used:
     int grade_index, nb_membership_function_parameters;
     char grade_name[20];
     */


    if (xmlStrcmp(cur->name, (const xmlChar *) "grade") == 0) {
        for (attr_node2 = cur->properties; attr_node2; attr_node2 = attr_node2->next) {
            /*
            if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_index") == 0) {
                grade_index = atoi((const char *) attr_node2->children->content);

            } else if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_name") == 0) {
                strncpy(grade_name, attr_node2->children->content, 20);

            } else */ if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_value") == 0) {
                grade_value = atoi((const char *) attr_node2->children->content);

            }
        }
    }


    cur = cur->xmlChildrenNode;

    while (cur != NULL) {

        if (xmlStrcmp(cur->name, (const xmlChar *) "membership_function_type") == 0) {
            membership_function_type = atoi((const char *) cur->children->content);
        /*
        } else if (xmlStrcmp(cur->name, (const xmlChar *) "nb_membership_function_parameters") == 0) {
            nb_membership_function_parameters = atoi((const char *) cur->children->content);
        */
        } else if (xmlStrcmp(cur->name, (const xmlChar *) "parameters") == 0)

            parseNodeparameter(cur, grade_value ,membership_function_type, metric_index);

        cur = cur->next;


    }
    return;
}
/*void parseNodekpigrades(xmlNodePtr cur, metric_t * metric, application_quality_estimation_t * application) {

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "grade") == 0) {
            parseNodekpigrade(cur, metric, application);

        }
        cur = cur->next;
    }
    return;
}*/


void parseNodegrades(xmlNodePtr cur, metric_t * metric) {

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "grade") == 0) {
            parseNodegrade(cur, metric);

        }
        cur = cur->next;
    }
    return;
}

void parseNodekpi(xmlNodePtr cur, application_quality_estimation_t * application) {

    metric_t * metric = NULL;

    int metric_id = 0;
    double metric_range_low = 0.0, metric_range_high = 0.0;
    /* Those are set, but not used:
    int metric_index, nb_grades;
    char metric_name[20];
    */

    xmlAttr *attr_node1 = NULL;
    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_id") == 0) {
            metric_id = atoi((const char *) attr_node1->children->content);
        /*
        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_name") == 0) {
            strncpy(metric_name, attr_node1->children->content, 20);

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_index") == 0) {
            metric_index = atoi((const char *) attr_node1->children->content);

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "nb_grades") == 0) {
            nb_grades = atoi((const char *) attr_node1->children->content);
        */
        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_low") == 0) {
            metric_range_low = atof((const char *) attr_node1->children->content);

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_high") == 0) {
            metric_range_high = atof((const char *) attr_node1->children->content);

        }


    }
    metric = init_new_metric_struct(metric_id, metric_range_low, metric_range_high);

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "grades") == 0) {
            parseNodegrades(cur, metric);
        }
if (xmlStrcmp(cur->name, (const xmlChar *) "index") == 0) {
            parseNodegrades(cur, metric);
        }

        cur = cur->next;
    }

    register_metric_with_application_struct(application, metric, METRIC);

}

void parseNodeIndexs(xmlNodePtr cur, application_quality_estimation_t * application) {

    metric_t * metric = NULL;
    int metric_id = 0;
    double metric_range_low = 0.0, metric_range_high = 0.0;
    /*
    int metric_index, nb_grades;
    char metric_name[20];
    */


    xmlAttr *attr_node1 = NULL;


    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_id") == 0) {
            metric_id = atoi((const char *) attr_node1->children->content);
        /*
        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_name") == 0) {
            strncpy(metric_name, attr_node1->children->content, 20);

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_index") == 0) {
            metric_index = atoi((const char *) attr_node1->children->content);

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "nb_grades") == 0) {
            nb_grades = atoi((const char *) attr_node1->children->content);
        */
        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_low") == 0) {
            metric_range_low = atof((const char *) attr_node1->children->content);

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_high") == 0) {
            metric_range_high = atof((const char *) attr_node1->children->content);

        }


    }
    metric = init_new_metric_struct(metric_id, metric_range_low, metric_range_high);

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {

        if (xmlStrcmp(cur->name, (const xmlChar *) "index") == 0) {
            parseNodegrades(cur, metric);
        }
        cur = cur->next;
    }
    register_metric_with_application_struct(application, metric, QUALITY_INDEX);
    return;
}

void parseNodekpis(xmlNodePtr cur, application_quality_estimation_t * application) {

    cur = cur->xmlChildrenNode;



    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "kpi") == 0) {
            parseNodekpi(cur, application);
        }

        if (xmlStrcmp(cur->name, (const xmlChar *) "indexs") == 0) {
            parseNodeIndexs(cur, application);
            //parseNodekpi(cur, application);
        }

        cur = cur->next;

    }
    return;
}

void parseNoderuleselementindex(xmlNodePtr cur, application_quality_estimation_t * application, rule_t * rule) {

    xmlAttr * attr_node1 = NULL;



    int metric_id = 0;
    int grade_value = 0;


    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_id") == 0) {
            metric_id = atoi((const char *) attr_node1->children->content);

        }

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "grade_value") == 0) {
            grade_value = atoi((const char *) attr_node1->children->content);

        }

    }
    register_metric_with_grade_to_rule_struct(application, rule, metric_id, grade_value);

    return;
}

void parseNoderuleselement(xmlNodePtr cur, application_quality_estimation_t * application, rule_t * rule) {
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "element") == 0) {
            parseNoderuleselementindex(cur, application, rule);
        }
        cur = cur->next;

    }

    return;

}

void parseNodeoutputelementindex(xmlNodePtr cur, application_quality_estimation_t * application, rule_t * rule)
 {

    xmlAttr * attr_node1 = NULL;


    int metric_id = 0;
    int grade_value = 0;


    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_id") == 0) {
            metric_id = atoi((const char *) attr_node1->children->content);

        }

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "grade_value") == 0) {
            grade_value = atoi((const char *) attr_node1->children->content);

        }

    }

    register_quality_estimation_metric_with_grade_to_rule_struct(application, rule, metric_id, grade_value);

    return;
}

void parseNodeoutputelement(xmlNodePtr cur, application_quality_estimation_t * application, rule_t * rule) {
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "element") == 0) {
            parseNodeoutputelementindex(cur, application, rule);
        }
        cur = cur->next;

    }

    return;

}

void parseNoderule(xmlNodePtr cur, application_quality_estimation_t * application,rule_t * rule, struct application_quality_estimation_rules_struct * quality_estimation_rules) {
/*
    int rule_type, nb_elements;

    xmlAttr * attr_node1 = NULL;

    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "rule_type") == 0) {
            rule_type = atoi((const char *) attr_node1->children->content);

        }
        else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "nb_elements") == 0) {
            nb_elements = atoi((const char *) attr_node1->children->content);

        }

    }
*/
    cur = cur->xmlChildrenNode;    

    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "rules_elements") == 0) {
            parseNoderuleselement(cur, application, rule);
        }

        if (xmlStrcmp(cur->name, (const xmlChar *) "output_elements") == 0) {
            parseNodeoutputelement(cur, application, rule);
        }

        cur = cur->next;

    }
    register_application_quality_estimation_rule(quality_estimation_rules, rule);
    return;

}

struct application_quality_estimation_rules_struct * parseNoderules(xmlNodePtr cur, application_quality_estimation_t * application) {
    /* Those are set but not used
    int nb_rules;
    int aggregation_type;
    */
    struct application_quality_estimation_rules_struct * quality_estimation_rules = init_new_app_quality_estimation_rules(SUM_AGGREGATION);
    rule_t * rule = NULL;
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
/*
        if (xmlStrcmp(cur->name, (const xmlChar *) "nb_rules") == 0) {

            nb_rules = atoi((const char *) cur->children->content);

        } else if (xmlStrcmp(cur->name, (const xmlChar *) "aggregation_type") == 0) {
            aggregation_type = atoi((const char *) cur->children->content);

        }
*/
        if (xmlStrcmp(cur->name, (const xmlChar *) "rule") == 0) {
            rule = init_new_rule_struct(AND_RULE);
            parseNoderule(cur, application,rule, quality_estimation_rules);

        }

         cur = cur->next;


    }

    return quality_estimation_rules;
}

application_quality_estimation_t * application_quality_estimation_xml_parser(char *docname) {

    application_quality_estimation_t * application = NULL;

    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlAttr *attr_node = NULL;

    int app_id;



    struct application_quality_estimation_rules_struct * quality_estimation_rules = NULL;


    doc = xmlParseFile(docname);

    if (doc == NULL) {
        die("Document parsing failed. \n");
        return NULL;
    }

    cur = xmlDocGetRootElement(doc); //Gets the root element of the XML Doc


    if (cur == NULL) {
        xmlFreeDoc(doc);
        die("Document is Empty!!!\n");
    }


    for (attr_node = cur->properties; attr_node; attr_node = attr_node->next) {

        if (xmlStrcmp(attr_node->name, (const xmlChar *) "app_id") == 0) {
            app_id = atoi((const char *) attr_node->children->content);
            application = init_new_application_quality_estimation_struct(app_id);

        }

        else if (xmlStrcmp(attr_node->name, (const xmlChar *) "nb_metrics") == 0) {

        } else if (xmlStrcmp(attr_node->name, (const xmlChar *) "nb_estimation_metrics") == 0) {

        }

    }

    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
        if ((xmlStrcmp(cur->name, (const xmlChar *) "kpis")) == 0) {
            parseNodekpis(cur, application);
        }


        if ((xmlStrcmp(cur->name, (const xmlChar *) "rules")) == 0) {
            quality_estimation_rules = parseNoderules(cur, application);
        }

        cur = cur->next;

    }

    register_estimation_rules_with_quality_metric(application, quality_estimation_rules, 3);

    xmlFreeDoc(doc);

    return application;
}






