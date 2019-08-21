#include <err.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <ei.h>

static nfc_device *pnd = NULL;
static nfc_context *context;


int is_ready(int fd) {
    fd_set fdset;
    struct timeval timeout;
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    timeout.tv_sec = 0;
    timeout.tv_usec = 1;
    return select(fd+1, &fdset, NULL, NULL, &timeout) == 1 ? 1 : 0;
}


static void stop_polling(int sig)
{
    (void) sig;
    if (pnd != NULL)
        nfc_abort_command(pnd);
    else {
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
}


/**
 * @brief Synchronously send a response back to Erlang
 *
 * @param response what to send back
 */
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

/*
void send_tag(const char *uid, size_t uid_len, char* tag_type) {
    char resp[1024];
    int resp_index = sizeof(uint16_t); // Space for payload size
    ei_encode_version(resp, &resp_index);

    ei_encode_tuple_header(resp, &resp_index, 3);

    ei_encode_atom(resp, &resp_index, "tag");
    ei_encode_binary(resp, &resp_index, uid, uid_len);
    ei_encode_binary(resp, &resp_index, tag_type);

    erlcmd_send(resp, resp_index);
}*/

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

void send_ping() {
    char resp[1024];
    int resp_index = sizeof(uint16_t); // Space for payload size
    ei_encode_version(resp, &resp_index);
    ei_encode_tuple_header(resp, &resp_index, 1);
    ei_encode_atom(resp, &resp_index, "ping");
    erlcmd_send(resp, resp_index);
}
/*
void send_tag(const char *uid, size_t uid_len, char *ndef, size_t ndef_len) {
    char resp[1024];
    int resp_index = sizeof(uint16_t); // Space for payload size
    ei_encode_version(resp, &resp_index);

    ei_encode_tuple_header(resp, &resp_index, 3);
    ei_encode_atom(resp, &resp_index, "tag");
    ei_encode_binary(resp, &resp_index, uid, uid_len);
    ei_encode_binary(resp, &resp_index, ndef, ndef_len);

    erlcmd_send(resp, resp_index);
}
*/
int card_transmit(nfc_device *pnd, uint8_t * capdu, size_t capdulen, uint8_t * rapdu, size_t * rapdulen)
{
  size_t  szPos;
  int retry = 1;
  int res = 0;
  while ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, -1) < 0) && (retry > 0)) {
    printf("RETRY\n");
    nfc_perror(pnd, "nfc_initiator_transceive_bytes");
    retry --;
  };
  if (retry == 0){
    printf("command failed \n");
    return -1;
  }else
    return 0;

}


int select_application_id(nfc_device *pnd) {
    uint8_t rapdu[264];
    size_t rapdulen = 264 ;
    uint8_t select_application_apdu[12];
    memcpy(select_application_apdu, "\x00\xA4\x04\x00\x07\xD2\x76\x00\x00\x85\x01\x01", 12);
    return card_transmit(pnd, select_application_apdu, 12,rapdu, &rapdulen);
}


int select_ndef_file(nfc_device *pnd) {
    uint8_t rapdu[264];
    size_t rapdulen = sizeof(rapdu);
    uint8_t select_ndef_file_apdu[7];
    memcpy(select_ndef_file_apdu, "\x00\xA4\x00\x0C\x02\xE1\x04", 7);
    return card_transmit(pnd, select_ndef_file_apdu, 7,rapdu, &rapdulen);
}

int read_ndef_file(nfc_device *pnd, uint8_t * rapdu) {
    int res;
    size_t rapdulen = 264;
    uint8_t get_file_size_apdu[5];
    memcpy(get_file_size_apdu, "\x00\xB0\x00\x00\x02", 5);
    card_transmit(pnd,  get_file_size_apdu, 5, rapdu, &rapdulen );
    rapdulen = rapdu[1];
    int size = rapdu[1] -2;
    uint8_t get_file_apdu[5] = { 0x00, 0xB0, 0x00, 0x02, size };
    size_t szPos;
    res = card_transmit(pnd, get_file_apdu, 5, rapdu, &rapdulen);
    if (res == -1){
        return res;
    }
    return size;
}



int read_ndef(nfc_device *pnd, uint8_t * rapdu ){
    select_application_id(pnd);
    select_ndef_file(pnd);
    return read_ndef_file(pnd, rapdu);
}

int read_vault_ic_sn(nfc_device *pnd, nfc_target nt, uint8_t * rapdu){
    uint8_t get_info_apdu[5];
    size_t rapdulen = 264;

    if (nt.nti.nbi.abtApplicationData[2] <= 2)
        memcpy(get_info_apdu, "\x80\x01\x00\x00\x35", 5);
    else
        memcpy(get_info_apdu, "\x80\x01\x00\x00\x38", 5);

    return card_transmit(pnd, get_info_apdu, 5, rapdu, &rapdulen);
}

int read_mifare_sn(nfc_device *pnd, nfc_target nt, uint8_t * sn_str, int * opening_detection, int * opening_detection_status){
    uint8_t rapdu[264];
    size_t rapdulen = 264;

    char buffer[10];
    char *p;
    char sn_str2[23];
    size_t  szPos;
    p = sn_str;
    for (szPos = 0; szPos < nt.nti.nai.szUidLen; szPos++) {
        sprintf(p, "%02X", nt.nti.nai.abtUid[szPos]);
        p += 2;
    }
    *p = 0;

    memcpy(sn_str, &nt.nti.nai.abtUid, nt.nti.nai.szUidLen);

    uint8_t read_page[2]= {0x30, 0x29};
    //card_transmit(pnd, read_page, 2, rapdu, &rapdulen);

    // int openFlagPosition = ((rapdu[2] * 4) + ((rapdu[1] && 0b00110000) >> 4) + 15);
     int openFlagPage = 16; //openFlagPosition / 4;
     int openFlagByte = 3; //openFlagPosition % 4;
     
     uint8_t read_opening_page[2] = {0x30, openFlagPage};
     card_transmit(pnd, read_opening_page, 2, rapdu, &rapdulen);
     *opening_detection = 1;
     if( rapdu[openFlagByte] == 0x30){
         *opening_detection_status = 0;
      }else{
         *opening_detection_status = 1;
      }
     
     //memcpy(get_info_apdu, "\x80\x01\x00\x00\x35", 5);
     //sn_str = &nt.nti.nai.abtUid;
     return 0;
}

int main(int argc, const char *argv[])
{
    signal(SIGINT, stop_polling);

    // Display libnfc version
    const char *acLibnfcVersion = nfc_version();

    uint8_t capdu[264];
    uint8_t rapdu[264];
    size_t rapdulen = 264;
    size_t ndef_len = 0;

    fprintf(stderr, "%s uses libnfc %s\n", argv[0], acLibnfcVersion);

    static const nfc_modulation nmVaultIC = {
        .nmt = NMT_ISO14443B,
        .nbr = NBR_106,
    };

    static const nfc_modulation nmMifare = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106,
    };

    nfc_target nt;

    nfc_init(&context);
    if (context == NULL) {
        fprintf(stderr, "Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }

    pnd = nfc_open(context, "pn532_i2c:/dev/i2c-1");


    if (pnd == NULL) {
        fprintf(stderr, "Unable to open NFC device.\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }


    // Let the device only try once to find a tag
    if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));
    printf("Starting\n");
    char buffer[10];
    char *p;
    char sn_str[23];
    char ndef_str[50];

    for (;;) {

        while (is_ready(fileno(stdin))) {
            if (!read(fileno(stdin), buffer, sizeof(buffer))) {
                fprintf(stderr, "Done.\n");
                nfc_abort_command(pnd);
                nfc_exit(context);
                exit(0);
            } else {
                fprintf(stderr, "data.. %s\n", buffer);
            }
        }

        // Try to find a VaultIC tag
        send_ping();
        int opening_detection = 0;
        int opening_detection_status = 1;
        int mifare_presence = -1;
        int vault_ic_presence = 0; //nfc_initiator_select_passive_target(pnd, nmVaultIC, NULL, 0, &nt);

      //  if (vault_ic_presence <= 0){
            mifare_presence = nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt);
      //  }

        if (vault_ic_presence <= 0 && mifare_presence <=0) {
            usleep(100 * 1000);
            //fprintf("select passive %d\n",nfc_initiator_select_passive_target(pnd, nmVaultIC, NULL, 0, &nt));
            continue;
        }

        if(vault_ic_presence == 1 && !read_vault_ic_sn(pnd, nt, rapdu)){
            memcpy(&sn_str, &rapdu[32], 8);
            send_tag(sn_str, 8, rapdu[53], rapdu[54], "VaultIC");
        };

        if(mifare_presence == 1 && !read_mifare_sn(pnd, nt, rapdu, &opening_detection, &opening_detection_status)){
            //memcpy(&sn_str, &rapdu[0], 8);
            send_tag(rapdu, 7, opening_detection, opening_detection_status, "Sic43NT");
        };


        while (0 == nfc_initiator_target_is_present(pnd, NULL)) {}

        usleep(200 * 1000);

    }

    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_SUCCESS);
}
