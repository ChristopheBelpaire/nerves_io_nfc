#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>
#include <ei.h>
#include "linux_nfc_api.h"

pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

nfcTagCallback_t g_TagCB;
nfc_tag_info_t g_tagInfos;

struct Response{
    unsigned char *apdu[255];
    int length;
}Response;

struct Tag{
    char type[255];
    int open;
    int openable;
    uint8_t uid[255];
    size_t uid_len;
}Tag;

void onTagArrival(nfc_tag_info_t *pTagInfo){
    g_tagInfos = *pTagInfo;
    pthread_cond_signal(&condition);
}

void onTagDeparture(void){}

void erlcmd_send(char *response, size_t len)
{
    uint16_t be_len = htons(len - sizeof(uint16_t));
    memcpy(response, &be_len, sizeof(be_len));

    size_t wrote = 0;
    do {
        ssize_t amount_written = write(STDOUT_FILENO, response + wrote, len - wrote);
        if (amount_written < 0) {
            if (errno == EINTR)
                continue;

            //err(EXIT_FAILURE, "write");
            exit(0);
        }

        wrote += amount_written;
    } while (wrote < len);
}

void send_tag(const char *uid, size_t uid_len, uint8_t open_detection_status, uint8_t open_detection, char* tag_type) {
    char resp[1024];
    int resp_index = sizeof(uint16_t); // Space for payload size
    ei_encode_version(resp, &resp_index);

    ei_encode_tuple_header(resp, &resp_index, 5);

    ei_encode_atom(resp, &resp_index, "tag");
    ei_encode_binary(resp, &resp_index, uid, uid_len);
    ei_encode_boolean(resp, &resp_index, open_detection_status);
    ei_encode_boolean(resp, &resp_index, open_detection);

    ei_encode_atom(resp, &resp_index, tag_type);

    erlcmd_send(resp, resp_index);
}

void print_unsigned_char(unsigned char* apdu, int length){
   int i = 0;
   for(i = 0; i < length; i++){
        printf("%02X ", apdu[i]);
   }
   printf("\n");
}

void print_tag_infos(struct Tag tag){
    printf("----------------\n");
    printf("  Type: %s      \n", tag.type);
    printf("  Openable: %d  \n", tag.openable);
    printf("  Open: %d      \n", tag.open);
    printf("  UUID: ");
    print_unsigned_char(tag.uid, tag.uid_len);
    printf("----------------\n");
}

int process(){
    struct Response response;
    struct Tag tag;


    pthread_cond_wait(&condition, &mutex);

    strcpy(tag.type, "NULL");
    tag.open = 0;
    tag.openable = 0;
    tag.uid_len = 0;
    memset(response.apdu, 0x00, 255);

    switch (g_tagInfos.technology){
        case TARGET_TYPE_ISO14443_3A:{
            // Silicon Craft Tag

            // Check opening support
            unsigned char read_page_config[2] = {0x30, 0x2A};
            response.length = nfcTag_transceive(g_tagInfos.handle, read_page_config, sizeof(read_page_config), response.apdu, 255, 500);
            unsigned char* config_1 = response.apdu;
            if (config_1[2] == 0x18){
                strcpy(tag.type, "Sic43nt");
                tag.openable = 1;
            }else{
                strcpy(tag.type, "Sic43n1F");
            }

            // Check opening state
            unsigned char read_tamper_state[2] = {0xAF, 0x00};
            unsigned char is_open[2] = {0xFF, 0xFF};
            response.length = nfcTag_transceive(g_tagInfos.handle, read_tamper_state, sizeof(read_tamper_state), response.apdu, 255, 500);
            if (memcmp(response.apdu, is_open, 2) == 0){
                tag.open = 1;
            }

            // UUID
            memcpy(tag.uid, g_tagInfos.uid, 8);
            tag.uid_len = g_tagInfos.uid_length;
            break;
        }
        case TARGET_TYPE_ISO14443_3B:{
            //VaultIC Tag
            unsigned char get_info[5] = {0x80, 0x01, 0x00, 0x00, 0x38};
            unsigned char* temp[255];

            response.length = nfcTag_transceive(g_tagInfos.handle, get_info, sizeof(get_info), response.apdu, 58 , 100);
            //printf("Length: %d      \n", response.length);

            unsigned char* tag_infos = response.apdu;
            /*if(tag_infos[0] == 0x67){
                strcpy(tag.type, "VaultIC152");
                get_info[4] = 0x35;
                response.length = nfcTag_transceive(g_tagInfos.handle, get_info, sizeof(get_info), response.apdu, 255, 100);
                tag_infos = response.apdu;
            }else{*/
                strcpy(tag.type, "VaultIC154");

                // Check opening support
                tag.openable = tag_infos[53];

                // Check opening state
                tag.open = tag_infos[54];
            //}

            // UUID
            int i;
            for (i = 32; i < 32+8; i++){
                tag.uid[i-32] = tag_infos[i];
            }
            tag.uid_len = 8;
            break;
        }
        case TARGET_TYPE_ISO15693:{
            //ICODE TAG

            memcpy(tag.uid, g_tagInfos.uid, 8);
            tag.uid_len = g_tagInfos.uid_length;

            int bit36 = (tag.uid[4] & ( 1 << 3 )) >> 3 ;
            int bit37 = (tag.uid[4] & ( 1 << 4 )) >> 4 ;

            if(!bit37 && !bit36){strcpy(tag.type, "IcodeSLI");}
            if( bit37 && !bit36){strcpy(tag.type, "IcodeSLIX");}
            if(!bit37 &&  bit36){strcpy(tag.type, "IcodeSLIX2");}
            if( bit37 &&  bit36){strcpy(tag.type, "IcodeDNA");}

            // UUID
            int i;
            uint8_t reversed_uid[255];
            for(i = 0; i < tag.uid_len+1; i++){
                reversed_uid[tag.uid_len-1-i] = tag.uid[i];
            }
            memcpy(tag.uid, reversed_uid, 8);
            break;
        }
        case TARGET_TYPE_MIFARE_UL:{
            // NXP MIFARE OR NTAG TAG
            unsigned char get_version[1] = {0x60};
            response.length = nfcTag_transceive(g_tagInfos.handle, get_version, sizeof(get_version), response.apdu, 255, 500);

            unsigned char* version_infos = response.apdu;
            if (response.length == 1){
                strcpy(tag.type, "MifareUltralightC");
            }else{
                switch(version_infos[6]){
                    case 0x0F: strcpy(tag.type, "Ntag213"); break;
                    case 0x11: strcpy(tag.type, "Ntag215"); break;
                    case 0x13: strcpy(tag.type, "Ntag216"); break;
                }
            }

            //UUID
            tag.uid_len = g_tagInfos.uid_length;
            memcpy(tag.uid, g_tagInfos.uid, 8);
            break;
        }
    }
    //print_tag_infos(tag);

    send_tag(tag.uid, tag.uid_len, tag.openable, tag.open, tag.type);

    return 1;
}

int main(int argc, char ** argv) {
    //printf("START\n\n");
    int res = -1;
    g_TagCB.onTagArrival = onTagArrival;
    g_TagCB.onTagDeparture = onTagDeparture;
    nfcManager_doInitialize();
    nfcManager_registerTagCallback(&g_TagCB);
    nfcManager_enableDiscovery(DEFAULT_NFA_TECH_MASK, 0x01, 0, 0);
    while(1) {
        res = process();
    }
    nfcManager_doDeinitialize();
    return res;
}
