#include "ad.h"

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