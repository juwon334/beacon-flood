#include "ad.h"
#include <iostream>

int main() {
    const char *dev = "wlan0";  // 사용할 네트워크 인터페이스 이름
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "네트워크 인터페이스 '" << dev << "'를 열 수 없습니다: " << errbuf << std::endl;
        return 2;
    }

    cappacket packet;

    // 패킷 초기화
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
	
    FILE *ssid_file = fopen("ssid-list.txt", "r");
    if (ssid_file == NULL) {
        perror("파일을 열 수 없습니다");
        pcap_close(handle);
        return 2;
    }

    char ssid_line[256];
    while (fgets(ssid_line, sizeof(ssid_line), ssid_file) != NULL) {
        size_t ssid_len = strlen(ssid_line);
        if (ssid_line[ssid_len - 1] == '\n') {
            ssid_line[ssid_len - 1] = '\0';
            ssid_len--;
        }

        // 데이터 초기화 및 SSID 데이터 삽입
        memset(packet.beacon.data, 0, sizeof(packet.beacon.data));
        packet.beacon.data[0] = 0x00; // SSID 태그 번호
        packet.beacon.data[1] = ssid_len; // SSID 길이
        memcpy(packet.beacon.data + 2, ssid_line, ssid_len);

        // 추가 데이터
        const uint8_t additional_data[] = {
            0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
            0x00, 0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00
        };
        memcpy(packet.beacon.data + 2 + ssid_len, additional_data, 22);

        // 패킷 전송
        size_t packet_size = sizeof(packet.header) + sizeof(packet.beacon.header) + sizeof(packet.beacon.fixed) + 2 + ssid_len + 26;
        while(1){
			if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), packet_size) != 0) {
				fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
				sleep(3);
			}
		}
    }

    fclose(ssid_file);
    pcap_close(handle);
    return 0;
}