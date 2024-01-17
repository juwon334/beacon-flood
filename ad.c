#include "ad.h"

void usage() {
	printf("syntax: ./ad <interface>\n");
	printf("sample: ./ad wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

int main(int argc, char* argv[]) {
	char *dev = "wlan0";  // 사용할 네트워크 인터페이스 이름
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "네트워크 인터페이스 '%s'를 열 수 없습니다: %s\n", dev, errbuf);
		return 2;
	}
	struct cappacket packet;

	//802.11 header
	packet.header.it_version = 0x00;
	packet.header.it_pad = 0;
	packet.header.it_len = 32;
	packet.header.presentstruct.present1 = 0xa00040ae;
	packet.header.presentstruct.present2 = 0xa0000820;
	packet.header.presentstruct.present3 = 0x00000820;
	packet.header.np.ant1 = 0;
	packet.header.np.ant2 = 0;
	packet.header.np.cf = 0;
	packet.header.np.cflag = 0x00a0;
	packet.header.np.datarate = 0;
	packet.header.np.flag = 0x10;
	packet.header.np.pwr1 = 0xb4;
	packet.header.np.pwr2 = 0xb4;
	packet.header.np.pwr = 0;
	packet.header.np.rf = 0;
	packet.header.np.sq = 0;

	//beacon
	packet.beacon.header.bssid[0] = 0x88;
	packet.beacon.header.bssid[1] = 0xc3;
	packet.beacon.header.bssid[2] = 0x97;
	packet.beacon.header.bssid[3] = 0xc7;
	packet.beacon.header.bssid[4] = 0x1b;
	packet.beacon.header.bssid[5] = 0x05;
	packet.beacon.header.duration_id = 0;
	packet.beacon.header.frame_control = 0x80;
	for(int i =0;i<6;i++){
		packet.beacon.header.readdr1[i]= 0xff;
	}
	packet.beacon.header.sequence_control = 3626;
	packet.beacon.header.sourceaddr4[0] = 0x88;
	packet.beacon.header.sourceaddr4[1] = 0xc3;
	packet.beacon.header.sourceaddr4[2] = 0x97;
	packet.beacon.header.sourceaddr4[3] = 0xc7;
	packet.beacon.header.sourceaddr4[4] = 0x1b;
	packet.beacon.header.sourceaddr4[5] = 0x05;

	//tag
	packet.beacon.fixed.beacon_interval = 0x6400;
	packet.beacon.fixed.capabilities_info = 0x0011;
	for(int i =0;i<6;i++){
		packet.beacon.fixed.timestamp[i] = 0;
	}

	//ssid
	packet.beacon.ie.id = 0;
	packet.beacon.ie.length = 4;
	uint8_t ssiddata[] = {0x74, 0x65, 0x73, 0x74};
	memcpy(packet.beacon.ie.data, ssiddata, sizeof(ssiddata));

	//rsn
	packet.beacon.ie.id1 = 48;
	packet.beacon.ie.length1 = 20;
	uint8_t rsndata[] = {0x01, 0x00, 0x00, 0x0f, 0xac,0x04,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 
		0x00, 0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00};
	memcpy(packet.beacon.ie.data1, rsndata, sizeof(rsndata));

	while (1)
	{
		if (pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
			fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
			sleep(1);
			return 2;
		}   
	}
	
	pcap_close(handle);
	return 0;
}

