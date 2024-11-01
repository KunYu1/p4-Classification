#include "appClassification_pipeline1.p4"
#include "appClassification_pipeline2.p4"



Pipeline(IngressParser_1(),
         Ingress_1(),
         IngressDeparser_1(),
         EgressParser_1(),
         Egress_1(),
         EgressDeparser_1()) pipeline_profile_1;

Pipeline(IngressParser_2(),
         Ingress_2(),
         IngressDeparser_2(),
         EgressParser_2(),
         Egress_2(),
         EgressDeparser_2()) pipeline_profile_2;

Switch(pipeline_profile_1, pipeline_profile_2) main;
