#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <thread>
#include <pcap.h>

void sendPacket(const std::string& ssid, const std::string& dev, std::vector<u_char> packet_data) {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		std::cerr << "network interface'" << dev << "'is down: " << errbuf << std::endl;
		return;
	}
	std::cout << "thread : " << ssid;

	const std::vector<u_char> additional_data = {
		0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
		0x00, 0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00
	};

	packet_data.insert(packet_data.end(), additional_data.begin(), additional_data.end());

	std::cout << std::endl;
	while (true) {
		if (pcap_sendpacket(handle, packet_data.data(), packet_data.size()+4) != 0) {
			std::cerr << "Can not send packet : " << pcap_geterr(handle) << " for SSID: " << ssid << std::endl;
		}
	}

	pcap_close(handle);
}

int main() {
	std::string dev = "wlan0";
	std::vector<std::string> ssids;
	std::ifstream ssid_file("ssid-list.txt");
	std::string ssid;

	while (std::getline(ssid_file, ssid)) {
		if (ssid.empty()) continue;
		ssids.push_back(ssid);
	}

	uint8_t bytes[69] = {
		0x00 ,0x00 ,0x20 ,0x00 ,0xae ,0x40 ,0x00 ,0xa0 ,0x20 ,0x08,
		0x00 ,0xa0 ,0x20 ,0x08 ,0x00 ,0x00 ,0x10 ,0x02 ,0x8a ,0x09,
		0xa0 ,0x00 ,0xb4 ,0x00 ,0x5a ,0x00 ,0x00 ,0x00 ,0xae ,0x00,
		0xae ,0x01, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0x88, 0xc3, 0x97, 0xc7, 0x1b, 0x05, 0x88, 0xc3,
		0x97, 0xc7, 0x1b, 0x05, 0xa0, 0xe2, 0x80, 0x41, 0x7c, 0x60,
		0xdd, 0x00, 0x00, 0x00, 0x64, 0x00, 0x31, 0x04, 0x00
	};

	std::vector<std::thread> threads;
	for (const auto& ssid : ssids) {
		std::vector<u_char> packet_data(bytes, bytes + sizeof(bytes));
		packet_data.push_back(static_cast<u_char>(ssid.length()));
		packet_data.insert(packet_data.end(), ssid.begin(), ssid.end());
		threads.emplace_back(sendPacket, ssid, dev, packet_data);
	}

	for (auto& thread : threads) {
		if (thread.joinable()) {
			thread.join();
		}
	}

	return 0;
}
