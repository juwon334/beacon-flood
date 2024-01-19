#include "ad.h"

void sendPacket(const std::string& ssid, const std::string& dev, cappacket& templatePacket) {
	char errbuf[PCAP_ERRBUF_SIZE];
	std::cout << "ssid : " << ssid << std::endl;
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "네트워크 인터페이스 '" << dev << "'를 열 수 없습니다: " << errbuf << std::endl;
        return;
    }
    size_t ssid_len = ssid.length();

    cappacket packet = templatePacket;
    memset(packet.beacon.data, 0, sizeof(packet.beacon.data));
    packet.beacon.data[0] = 0x00;
    packet.beacon.data[1] = ssid_len;
    memcpy(packet.beacon.data + 2, ssid.c_str(), ssid_len);

    // 추가 데이터
    const uint8_t additional_data[] = {
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00
    };
    memcpy(packet.beacon.data + 2 + ssid_len, additional_data, 22);

    size_t packet_size = sizeof(packet.header) + sizeof(packet.beacon.header) + sizeof(packet.beacon.fixed) + 2 + ssid_len + 30;

    while (true) {
        if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), packet_size) != 0) {
            std::cerr << "패킷 전송 실패: " << pcap_geterr(handle) << " for SSID: " << ssid << std::endl;
        }
    }
	pcap_close(handle);
}

int main() {
	std::string dev = "wlan0";
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
	
  	std::vector<std::string> ssids;
    std::ifstream ssid_file("ssid-list.txt");
    std::string ssid;

    while (std::getline(ssid_file, ssid)) {
        if (ssid.empty()) continue;
        ssids.push_back(ssid);
    }

    std::vector<std::thread> threads;
    for (const auto& ssid : ssids) {
        std::cout << "Creating thread for SSID: " << ssid << std::endl;
        threads.emplace_back(sendPacket, ssid, dev, std::ref(packet));
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    return 0;
}