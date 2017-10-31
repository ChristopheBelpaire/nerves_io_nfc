gcc -DHAVE_CONFIG_H -I.  -I./src/include -I./src/libnfc-nci/include -I./src/libnfc-nci/gki/ulinux -I./src/libnfc-nci/gki/common -I./src/libnfc-nci/nfa/include -I./src/libnfc-nci/nfa/int -I./src/libnfc-nci/nfc/include -I./src/libnfc-nci/nfc/int -I./src/libnfc-nci/hal/include -I./src/libnfc-nci/hal/int -I./src/halimpl/include -I./src/halimpl/pn54x/utils -I./src/halimpl/pn54x/inc -I./src/halimpl/pn54x/common -I./src/halimpl/pn54x/dnld -I./src/halimpl/pn54x/hal -I./src/halimpl/pn54x/log -I./src/halimpl/pn54x/tml -I./src/halimpl/pn54x/self-test -I./src/service/interface -I./src/service/utils -I./src/service/extns/inc -I./src/service/extns/src/common -I./src/service/extns/src/mifare -DPN547C2=1 -DPN548C2=2 -DPN551C2=3 -pthread -w -g -DNFC_NXP_NOT_OPEN_INCLUDED=TRUE -DNXP_HW_SELF_TEST -DDEBUG -DNXP_NFC_NATIVE_ENABLE_HCE=TRUE -DNFC_NXP_LLCP_SECURED_P2P=TRUE   -DNFC_NXP_CHIP_TYPE=PN548C2 -DNXP_CHIP_NAME=\"pn7150\" -DPH_NCI_NXP_HAL_ENABLE_FW_DOWNLOAD=FALSE -I./demoapp -I./src/include  -I/opt/openssl/include   -g -O2 -MT demoapp/main.o -MD -MP -MF $depbase.Tpo -c -o main.o pn_7150.c

/bin/bash ~/linux_libnfc-nci/libtool --tag=CC   --mode=link gcc  -g -O2 -pthread -ldl -lrt -Bstatic -lnfc_nci_linux  -L/opt/openssl/lib -lcrypto -lssl -lei -o main main.o
