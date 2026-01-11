#include <pcap.h>
#include <iostream>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// 통계 구조체

struct Stats {
    uint64_t packet_count = 0;
    uint64_t byte_count   = 0;

    // PPS(초당 패킷 수) 윈도우
    uint64_t window_packets = 0;
    std::chrono::steady_clock::time_point window_start =
        std::chrono::steady_clock::now();
};

// IP → Stats
static std::unordered_map<uint32_t, Stats> ip_stats;

//큐에 저장할 패킷 단위 (Producer → Consumer)

struct PacketItem {
    std::vector<u_char> data; 
    uint32_t caplen = 0;
    uint32_t len    = 0;     
};

//스레드 동기화용 전역 객체

static std::deque<PacketItem> g_queue;
static std::mutex g_mtx;
static std::condition_variable g_cv;
static std::atomic<bool> g_running{true};

static constexpr size_t MAX_QUEUE_SIZE = 5000;

// 링크 계층 오프셋 계산

static bool get_l2_offset(int dlt, int& offset) {
    if (dlt == DLT_EN10MB) { offset = 14; return true; }   // Ethernet
    if (dlt == DLT_LINUX_SLL) { offset = 16; return true; }
    if (dlt == DLT_LINUX_SLL2) { offset = 20; return true; }
    return false;
}

// Consumer: 패킷 분석 + 통계 + PPS 탐지
 *
static void analyze_packet(pcap_t* handle, const PacketItem& item) {
    int dlt = pcap_datalink(handle);

    int l2_offset = 0;
    if (!get_l2_offset(dlt, l2_offset)) return;
    if (item.caplen < l2_offset + sizeof(iphdr)) return;

    const u_char* packet = item.data.data();
    const iphdr* ip =
        reinterpret_cast<const iphdr*>(packet + l2_offset);

    // IPv4만 처리
    if (ip->version != 4) return;

    int ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20) return;
    if (item.caplen < l2_offset + ip_header_len) return;

    // ip통계
    uint32_t src_ip_raw = ip->saddr;
    Stats& st = ip_stats[src_ip_raw];
    st.packet_count++;
    st.byte_count += item.len;

    // pps 탐지
    using clock = std::chrono::steady_clock;
    auto now = clock::now();

    auto elapsed =
        std::chrono::duration_cast<std::chrono::seconds>(
            now - st.window_start).count();

    if (elapsed >= 1) {
        st.window_packets = 0;
        st.window_start = now;
    }

    st.window_packets++;

    constexpr uint64_t PPS_THRESHOLD = 10; //테스트

    if (st.window_packets > PPS_THRESHOLD) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_ip_raw, ip_str, sizeof(ip_str));

        std::cout << "[!!] PPS threshold exceeded: "
                  << ip_str << " pps=" << st.window_packets << "\n";
        std::cout << "[SEC] would block: iptables -A INPUT -s "
                  << ip_str << " -j DROP\n";
    }

    //로그
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    std::cout << "[+] IPv4 " << src_ip << " -> " << dst_ip
              << " proto=" << (int)ip->protocol
              << " total_len=" << ntohs(ip->tot_len)
              << " caplen=" << item.caplen << "\n";

    const u_char* l4 = packet + l2_offset + ip_header_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (item.caplen < l2_offset + ip_header_len + sizeof(tcphdr)) return;
        const tcphdr* tcp =
            reinterpret_cast<const tcphdr*>(l4);

        std::cout << "    TCP "
                  << ntohs(tcp->source) << " -> "
                  << ntohs(tcp->dest)
                  << " flags="
                  << (tcp->syn ? "S" : "-")
                  << (tcp->ack ? "A" : "-")
                  << "\n";
    } else if (ip->protocol == IPPROTO_UDP) {
        if (item.caplen < l2_offset + ip_header_len + sizeof(udphdr)) return;
        const udphdr* udp =
            reinterpret_cast<const udphdr*>(l4);

        std::cout << "    UDP "
                  << ntohs(udp->source) << " -> "
                  << ntohs(udp->dest)
                  << " len=" << ntohs(udp->len)
                  << "\n";
    }
}

// Producer: libpcap 콜백

static void pcap_producer_cb(u_char*,
                             const struct pcap_pkthdr* header,
                             const u_char* packet)
{
    PacketItem item;
    item.caplen = header->caplen;
    item.len    = header->len;
    item.data.assign(packet, packet + header->caplen);

    {
        std::unique_lock<std::mutex> lk(g_mtx);
        if (g_queue.size() >= MAX_QUEUE_SIZE) return; 
        g_queue.push_back(std::move(item));
    }
    g_cv.notify_one();
}

// Consumer 스레드 함수

static void consumer_thread(pcap_t* handle) {
    while (g_running.load()) {
        PacketItem item;

        {
            std::unique_lock<std::mutex> lk(g_mtx);
            g_cv.wait(lk, []{
                return !g_queue.empty() || !g_running.load();
            });

            if (!g_running.load() && g_queue.empty()) break;

            item = std::move(g_queue.front());
            g_queue.pop_front();
        }

        analyze_packet(handle, item);
    }
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        std::cerr << "pcap_findalldevs failed: " << errbuf << "\n";
        return 1;
    }

    pcap_if_t* dev = alldevs;
    std::cout << "Using device: " << dev->name << "\n";

    pcap_t* handle =
        pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Consumer 스레드 시작
    std::thread t_consumer(consumer_thread, handle);

    // Producer 실행 (테스트용 50개 캡처)
    pcap_loop(handle, 50, pcap_producer_cb, nullptr);

    // 종료 처리
    g_running.store(false);
    g_cv.notify_all();
    t_consumer.join();

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    //최종 통계 출력
    std::cout << "\n==== IP Statistics ====\n";
    for (const auto& [ip_raw, st] : ip_stats) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_raw, ip_str, sizeof(ip_str));

        std::cout << ip_str
                  << " packets=" << st.packet_count
                  << " bytes=" << st.byte_count
                  << "\n";
    }

    return 0;
}
