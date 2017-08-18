#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/filter.h>

// tcpdump -dd生成出的伪代码块
// instruction format:
// +----------------+--------+--------+
// |   16 bits      | 8 bits | 8 bits |
// | operation code |   jt   |   jf   |
// +----------------+--------+--------+
// | (MSB)         k:32         (LSB) |
// +----------------------------------+
static struct sock_filter code[] = {
    { 0x28, 0, 0, 0x0000000c },             // (000) ldh      [12]
    { 0x15, 0, 4, 0x000086dd },             // (001) jeq      #0x86dd          jt 2     jf 6
    { 0x30, 0, 0, 0x00000014 },             // (002) ldb      [20]
    { 0x15, 0, 11, 0x00000006 },            // (003) jeq      #0x6             jt 4     jf 15
    { 0x28, 0, 0, 0x00000038 },             // (004) ldh      [56]
    { 0x15, 8, 9, 0x00000438 },             // (005) jeq      #0x438           jt 14    jf 15
    { 0x15, 0, 8, 0x00000800 },             // (006) jeq      #0x800           jt 7     jf 15
    { 0x30, 0, 0, 0x00000017 },             // (007) ldb      [23]
    { 0x15, 0, 6, 0x00000006 },             // (008) jeq      #0x6             jt 9     jf 15
    { 0x28, 0, 0, 0x00000014 },             // (009) ldh      [20]
    { 0x45, 4, 0, 0x00001fff },             // (010) jset     #0x1fff          jt 15    jf 11
    { 0xb1, 0, 0, 0x0000000e },             // (011) ldxb     4*([14]&0xf)
    { 0x48, 0, 0, 0x00000010 },             // (012) ldh      [x + 16]
    { 0x15, 0, 1, 0x00000438 },             // (013) jeq      #0x438           jt 14    jf 15
    { 0x6, 0, 0, 0x00040000 },              // (014) ret      #262144
    { 0x6, 0, 0, 0x00000000 },              // (015) ret      #0
};

int main(int argc, char **argv)
{
	int s;
	int bytes;
	char buf[4096];
	struct sockaddr_ll addr;
	struct iphdr *ip_header;
	char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];
	char *name;
	struct sock_fprog bpf = { sizeof(code)/sizeof(struct sock_filter), code };

	if (argc != 2) {
		printf("Usage: %s ifname\n", argv[0]);
		return 1;
	}

    // 1. 创建raw socket 
    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		printf("Create socket failed!\n");
		return 1;
	}

    // 2. 将socket绑定给指定的ethernet dev
	name = argv[1];                         // ethernet dev由参数1传入
	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_nametoindex(name);
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind to device %s failed!\n", name);
		return 1;
	}
    // 3. 利用SO_ATTACH_FILTER将bpf代码块传入内核
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
		printf("Attaching filter failed!\n");
		return 2;
	}
	
    for (;;) {
		bytes = recv(s, buf, sizeof(buf), 0);       // 4. 利用recv()获取符合条件的报文
		if (bytes < 1) {
			printf("recv date failed!\n");
			return -1;
		}

		ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
		inet_ntop(AF_INET, &ip_header->saddr, src_addr_str, sizeof(src_addr_str));
		inet_ntop(AF_INET, &ip_header->daddr, dst_addr_str, sizeof(dst_addr_str));
		printf("IPv%d proto=%d src=%s dst=%s\n",
				ip_header->version, ip_header->protocol, src_addr_str, dst_addr_str);
	}

	return 0;
}
