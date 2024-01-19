#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

struct present {
	u_int32_t present1;
	u_int32_t present2;
	u_int32_t present3;
};

struct nextpresent{
	u_int8_t flag;
	u_int8_t datarate;
	u_int16_t cf;
	u_int16_t cflag;
	u_int16_t pwr;
	u_int16_t sq;
	u_int16_t rf;
	u_int8_t pwr1;
	u_int8_t ant1;
	u_int8_t pwr2;
	u_int8_t ant2;
};

struct ieee80211_radiotap_header {
	u_int8_t        it_version;     /* set to 0 */
	u_int8_t        it_pad;
	u_int16_t       it_len;       /* entire length */
	struct present    presentstruct;
	struct nextpresent np;
} __attribute__((__packed__));


struct ieee80211_header {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t readdr1[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
	uint16_t sequence_control;
};

struct beacon_frame_fixed {
	u_int8_t timestamp[8];
	u_int16_t beacon_interval; 
	u_int16_t capabilities_info;
};

struct beacon_frame {
    struct ieee80211_header header;
    struct beacon_frame_fixed fixed;
    u_int8_t data[1024];  // std::vector를 사용한 동적 데이터
};

struct tag_rsn{
	uint8_t rsnid;
	uint8_t rsnlength;
	uint16_t version;
	uint32_t GroupCipherss;
	uint16_t pairwisesc;
};

struct cappacket{
	struct ieee80211_radiotap_header header;
	struct beacon_frame beacon;
};

void printBinary(unsigned int num) {
	unsigned int mask = 1 << (sizeof(num) * 8 - 1);

	for (int i = 0; i < sizeof(num) * 8; i++) {
		printf("%d", (num & mask) ? 1 : 0);
		mask >>= 1;
	}
	printf("\n");
}

void binaryToIntArray(unsigned int num, char *arr) {
	unsigned int mask = 1 << (sizeof(num) * 8 - 1);
	for (int i = 0; i < sizeof(num) * 8; i++) {
		arr[i] = (num & mask) ? 1 : 0;
		mask >>= 1;
	}
}

void print_addr(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
	printf("\n");
}

