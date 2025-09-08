/**
 * This example is intened to provide the list of available protocols and for each protocol, the list of its attributes
 * 
 * Compile this example with:
 * 
 * Linux:
 * $ gcc -o proto_attributes_iterator proto_attributes_iterator.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 * 
 * macOS (from MMT-DPI root directory):
 * $ clang -o proto_attributes_iterator src/examples/proto_attributes_iterator.c \
 *     -I sdk/include -L sdk/lib -lmmt_core -ldl \
 *     -Wl,-rpath,sdk/lib
 * 
 * macOS (if installed in /opt/mmt):
 * $ clang -o proto_attributes_iterator proto_attributes_iterator.c \
 *     -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl \
 *     -Wl,-rpath,/opt/mmt/dpi/lib
 * 
 * Then execute the program:
 * 
 * IMPORTANT for macOS: Set the plugin path before running:
 * $ export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib
 * 
 * $ ./proto_attributes_iterator > proto_attr_output.txt
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
	printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  
	printf("|\t\t MONTIMAGE\n");
	printf("|\t MMT-SDK version: %s\n",mmt_version());
	printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
	printf("|\t http://montimage.com\n");
	printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");  	
	
	init_extraction();

	iterate_through_protocols(protocols_iterator, NULL);

	close_extraction();

	return (EXIT_SUCCESS);
}

