/**
 * This example is intened to provide the list of available protocols and for each protocol, the list of its attributes
 * 
 * To run this example, mmt-sdk installing is required. After installing mmt-sdk, add the mmt library to project library path by following command:
 * 
 * export LD_LIBRARY_PATH=/opt/mmt/lib:/usr/local/lib:$LD_LIBRARY_PATH
 * 
 * Compile this example with:
 * 
 * gcc -I/opt/mmt/include -o proto_attributes_iterator proto_attributes_iterator.c -L/opt/mmt/lib -lmmt_core -ldl
 * 
 * Then execute the program:
 * 
 * ./proto_attributes_iterator > proto_attr_output.txt
 * 
 * The output in the file proto_attr_output.txt
 * 
 * 	That is it!
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include "mmt_core.h"

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
  printf("\tAttribute id %i --- Name %s \n", attribute->id, attribute->alias);
}

void protocols_iterator(uint32_t proto_id, void * args) {
  printf("Protocol id %i --- Name %s\n", proto_id, get_protocol_name_by_id(proto_id));
  iterate_through_protocol_attributes(proto_id, attributes_iterator, NULL);
}

int main(int argc, char** argv) {

  init_extraction();

  iterate_through_protocols(protocols_iterator, NULL);

  close_extraction();

  return (EXIT_SUCCESS);
}

