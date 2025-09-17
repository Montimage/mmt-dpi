/**
 * This example is intened to export the list of available protocols and for each protocol, the list of its attributes in .csv format
 * 
 * Compile this example with:
 * 
 * gcc -o mmt_export_info mmt_export_info.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 * 
 * macOS (from MMT-DPI root directory):
 * $ clang -o mmt_export_info src/examples/mmt_export_info.c -I sdk/include -L sdk/lib -lmmt_core -ldl -Wl,-rpath,sdk/lib
 * 
 * Then execute the program:
 * 
 * IMPORTANT for macOS: Set the environment before running:
 * $ export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib
 * $ export DYLD_LIBRARY_PATH=/path/to/mmt-dpi/sdk/lib:$DYLD_LIBRARY_PATH
 * 
 * ./mmt_export_info > list_proto_attribute.csv
 * 
 * The output is written to file list_proto_attribute.csv
 * 
 * 	That is it!
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include "mmt_core.h"

uint64_t nb_proto = 0;
uint64_t nb_attr = 0;

/**
 * @brief Repeat for all attributes of a protocol
 * 
 * @param attribute 
 * @param proto_id 
 * @param args 
 */
void attributes_iterator(attribute_metadata_t *attribute, uint32_t proto_id, void *args)
{
    nb_attr++;
    const char *proto_name = get_protocol_name_by_id(proto_id);
    printf("%i,%s,%i,%s\n", proto_id, proto_name, attribute->id, attribute->alias);
}

/**
 * @brief Repeat for all protocols  
 * 
 * @param proto_id 
 * @param args 
 */
void protocols_iterator(uint32_t proto_id, void *args)
{
    nb_proto++;
    iterate_through_protocol_attributes(proto_id, attributes_iterator, NULL);
}

int main(int argc, char **argv)
{

    init_extraction();

    printf("_proto_id, proto_name, attr_id, attr_name, version: %s\n", mmt_version());

    iterate_through_protocols(protocols_iterator, NULL);
    
    close_extraction();
    nb_proto = nb_proto - 2; // 2 protocols: unknown and meta
    printf("-1,Number of protocols,%lu,Not include UNKNOWN and META protocols\n",nb_proto);
    uint64_t nb_attr_real = nb_attr - (nb_proto - 1) * 9;
    printf("-1,Number of attributes (all),%lu\n", nb_attr);
    printf("-1,Number of attributes (no repeat),%lu\n", nb_attr_real);

    return (EXIT_SUCCESS);
}
