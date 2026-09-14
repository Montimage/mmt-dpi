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

/* NULL-checking accessor for the text carried by a node's first child.
 * Every former first-child text dereference goes through it, so a node
 * without children or without text yields an empty string instead of a
 * NULL dereference in atoi()/atof(). */
static const xmlChar * mmt_xml_children_content(const xmlNode * children) {
    const xmlChar * content = NULL;
    if (children != NULL)
        content = children->content;
    return (content != NULL) ? content : (const xmlChar *) "";
}

void parseNodeparameter(xmlNodePtr cur,int grade_value,int membership_function_type, metric_t * metric) {

    cur = cur->xmlChildrenNode;
  double  membership_function_parameters[4] = {0.0, 0.0, 0.0, 0.0};
    int i = 0;
    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "membership_function_parameters") == 0) {
            if (i < 4) {
                (membership_function_parameters[i]) = atof((const char *) mmt_xml_children_content(cur->children));
                i++;
            }
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
void parseNodegrade(xmlNodePtr cur, metric_t * metric_index) {

    xmlAttr *attr_node2 = NULL;
     int grade_value = 0, membership_function_type = 0;

    if (xmlStrcmp(cur->name, (const xmlChar *) "grade") == 0) {
        for (attr_node2 = cur->properties; attr_node2; attr_node2 = attr_node2->next) {
            if (xmlStrcmp(attr_node2->name, (const xmlChar *) "grade_value") == 0) {
                grade_value = atoi((const char *) mmt_xml_children_content(attr_node2->children));

            }
        }
    }


    cur = cur->xmlChildrenNode;

    while (cur != NULL) {

        if (xmlStrcmp(cur->name, (const xmlChar *) "membership_function_type") == 0) {
            membership_function_type = atoi((const char *) mmt_xml_children_content(cur->children));
        } else if (xmlStrcmp(cur->name, (const xmlChar *) "parameters") == 0)

            parseNodeparameter(cur, grade_value ,membership_function_type, metric_index);

        cur = cur->next;


    }
    return;
}


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

    xmlAttr *attr_node1 = NULL;
    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_id") == 0) {
            metric_id = atoi((const char *) mmt_xml_children_content(attr_node1->children));
        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_low") == 0) {
            metric_range_low = atof((const char *) mmt_xml_children_content(attr_node1->children));

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_high") == 0) {
            metric_range_high = atof((const char *) mmt_xml_children_content(attr_node1->children));

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


    xmlAttr *attr_node1 = NULL;


    for (attr_node1 = cur->properties; attr_node1; attr_node1 = attr_node1->next) {

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_id") == 0) {
            metric_id = atoi((const char *) mmt_xml_children_content(attr_node1->children));
        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_low") == 0) {
            metric_range_low = atof((const char *) mmt_xml_children_content(attr_node1->children));

        } else if (xmlStrcmp(attr_node1->name, (const xmlChar *) "metric_range_high") == 0) {
            metric_range_high = atof((const char *) mmt_xml_children_content(attr_node1->children));

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
            metric_id = atoi((const char *) mmt_xml_children_content(attr_node1->children));

        }

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "grade_value") == 0) {
            grade_value = atoi((const char *) mmt_xml_children_content(attr_node1->children));

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
            metric_id = atoi((const char *) mmt_xml_children_content(attr_node1->children));

        }

        if (xmlStrcmp(attr_node1->name, (const xmlChar *) "grade_value") == 0) {
            grade_value = atoi((const char *) mmt_xml_children_content(attr_node1->children));

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
    struct application_quality_estimation_rules_struct * quality_estimation_rules = init_new_app_quality_estimation_rules(SUM_AGGREGATION);
    rule_t * rule = NULL;
    cur = cur->xmlChildrenNode;

    while (cur != NULL) {
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
        return NULL;
    }


    for (attr_node = cur->properties; attr_node; attr_node = attr_node->next) {

        if (xmlStrcmp(attr_node->name, (const xmlChar *) "app_id") == 0) {
            app_id = atoi((const char *) mmt_xml_children_content(attr_node->children));
            application = init_new_application_quality_estimation_struct(app_id);

        }

        else if (xmlStrcmp(attr_node->name, (const xmlChar *) "nb_metrics") == 0) {

        } else if (xmlStrcmp(attr_node->name, (const xmlChar *) "nb_estimation_metrics") == 0) {

        }

    }

    /* Without an app_id there is no application struct to populate; bail
     * out before the node walkers dereference the NULL application. */
    if (application == NULL) {
        xmlFreeDoc(doc);
        die("Document has no app_id attribute!!!\n");
        return NULL;
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






