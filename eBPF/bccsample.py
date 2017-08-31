# coding: utf-8
#! /usr/bin/python

from bcc import BPF
import socket
import time

interface="ens160"
# BCC可以接受直接将BPF代码嵌入python code之中
# 为了方便展示笔者使用了这一功能
# 注意：prog中的中文注释是由于笔者需要写作之故加入，如果读者想尝试运行这段代码，
# 则请将中文全部删除，因为目前BCC还不支持在内嵌C代码中使用中文注释
prog = """
#include <net/sock.h>
#include <bcc/proto.h>

// BCC中专门为map定义了一系列的宏，以方便使用
// 宏中的struct下还定义了相应的函数，让开发者可以如C++一般操作map
// 这里笔者定义了一个array类型的map，名为my_map1
BPF_ARRAY(my_map1, long);
// BCC下的BPF程序中不再需要定义把函数或变量专门放置于某个section下了
int bpf_prog1(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    long *value;

    struct ethernet_t *eth = cursor_advance(cursor, sizeof(*eth));
    if (!(eth->type == 0x0800))
    {
        return 0;
    }
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    int index = ip->nextp;
    long zero = 0;  // BCC下的bpf书写还是有很多坑的
                    // 例如，这里如果不去定义一个局部变量zero，
                    // 而是直接用常量0作为lookup_or_init()的变量就会报错
    // map类下的各个方法的具体细节可以参照reference_guide.md
    value = my_map1.lookup_or_init(&index, &zero);
    if (value)
		__sync_fetch_and_add(value, skb->len);

    return 0;
}
"""
# 载入bpf代码
bpf = BPF(text=prog, debug = 0)
# 注入bpf_prog1函数
function = bpf.load_func("bpf_prog1", BPF.SOCKET_FILTER)
# 这是一段SOCKET_FILTER类型的BPF，所以需要挂载到某一个interface上
BPF.attach_raw_socket(function, interface)
# 利用map机制获取进出interface的各个协议的报文总长
bpf_map = bpf["my_map1"]
while 1:
    print ("TCP : {}, UDP : {}, ICMP: {}".format(
           bpf_map[socket.IPPROTO_TCP].value,
           bpf_map[socket.IPPROTO_UDP].value,
           bpf_map[socket.IPPROTO_ICMP].value))
    time.sleep(1)
