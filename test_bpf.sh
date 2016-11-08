#!/bin/sh

# requires: tc, clang, bpf_asm, tcpdump, fds_example.{cls,act} (patched for correct BPF_PROG_TYPE_* type)

set -x

function pause() {
	read
}

## classifier

umount /sys/fs/bpf/

# cbpf inline parsing
tc qdisc del dev lo clsact 2> /dev/null
tc qdisc add dev lo clsact

tc filter add dev lo ingress bpf bytecode '1,6 0 0 4294967295,' flowid 1:1 action drop
tc filter add dev lo egress  bpf bytecode '1,6 0 0 4294967295,' flowid 1:1 action drop

tc filter show dev lo ingress
tc filter show dev lo egress

# delete whole chain
tc filter del dev lo ingress
tc filter del dev lo egress

tc filter show dev lo ingress
tc filter show dev lo egress

tc qdisc del dev lo clsact

pause
# cbpf direct action
tc qdisc add dev lo clsact

tc filter add dev lo ingress bpf da bytecode '1,6 0 0 4294967295,' flowid 1:1
tc filter add dev lo ingress bpf da bc '1,6 0 0 4294967295,' flowid 1:1
tc filter add dev lo ingress bpf da run bc '1,6 0 0 4294967295,' flowid 1:1 action drop
tc filter show dev lo ingress

tc qdisc del dev lo clsact

pause
# cbpf from file
tc qdisc add dev lo clsact

tcpdump -ilo -ddd 'tcp[tcpflags] & tcp-syn != 0' | tr '\n' ',' > /tmp/tcp-syn
tc filter add dev lo ingress bpf bytecode-file /tmp/tcp-syn action drop
tc filter add dev lo ingress bpf bcf /tmp/tcp-syn action drop
tc filter add dev lo ingress bpf run bcf /tmp/tcp-syn action drop
tc filter show dev lo ingress

tc qdisc del dev lo clsact

pause
# tmp ebpf prog
cat <<EOF > /tmp/bpf-asm.c
ldh [12]
jne #0x800, drop
ldb [23]
jneq #6, drop
ret #-1
drop: ret #0
EOF
bpf_asm /tmp/bpf-asm.c > /tmp/bpf-asm.i

# cbpf from asm file
tc qdisc add dev lo clsact

tc filter add dev lo ingress bpf da bcf /tmp/bpf-asm.i
tc filter add dev lo ingress bpf da bc "`bpf_asm /tmp/bpf-asm.c`"
tc filter show dev lo ingress

tc qdisc del dev lo clsact

pause
# tmp ebpf prog
cat <<EOF > /tmp/bpf.c
#include <linux/bpf.h>

#ifndef __section
# define __section(x) __attribute__((section(x), used))
#endif

__section("classifier")
int x(struct __sk_buff *skb) {
	return 0;
}

__section("foobar")
int y(struct __sk_buff *skb) {
	return 0;
}

char __license[] __section("license") = "GPL";
EOF

clang -O2 -Wall -target bpf -c /tmp/bpf.c -o /tmp/bpf.o

# ebpf from obj
tc qdisc add dev lo clsact

tc filter add dev lo ingress bpf da obj /tmp/bpf.o
tc filter add dev lo egress bpf da obj /tmp/bpf.o
tc filter show dev lo ingress
tc filter show dev lo egress

tc filter add dev lo ingress bpf da obj /tmp/bpf.o sec classifier
tc filter add dev lo ingress bpf da object /tmp/bpf.o verb
tc filter add dev lo ingress bpf da object-file /tmp/bpf.o sec foobar verb
tc filter add dev lo ingress bpf da run object-file /tmp/bpf.o sec foobar
tc filter add dev lo ingress bpf da object-file /tmp/bpf.o sec fooba verb # will fail
tc filter add dev lo ingress bpf obj /tmp/bpf.o verb classid 1:1
tc filter add dev lo ingress bpf da obj /tmp/bpf.o action drop
tc filter add dev lo ingress bpf obj /tmp/bpf.o action drop
tc filter add dev lo ingress bpf run obj /tmp/bpf.o action drop
tc filter add dev lo ingress bpf run obj /tmp/bpf.o da
tc filter show dev lo ingress

tc qdisc del dev lo clsact

pause
# ebpf replace, delete
tc qdisc add dev lo clsact

tc filter add dev lo ingress pref 1 handle 1 bpf da obj /tmp/bpf.o
tc filter add dev lo ingress prio 1 handle 2 bpf da obj /tmp/bpf.o
tc filter add dev lo ingress prio 3 bpf da obj /tmp/bpf.o
tc filter show dev lo ingress

tc filter replace dev lo ingress pref 1 handle 1 bpf obj /tmp/bpf.o sec foobar action drop
tc filter show dev lo ingress

tc filter replace dev lo ingress pref 1 handle 1 bpf da obj /tmp/bpf.o verb
tc filter show dev lo ingress

tc filter replace dev lo ingress pref 1 handle 1 bpf bc '1,6 0 0 4294967295,' flowid 1:1
tc filter replace dev lo ingress pref 1 handle 5 bpf bc '1,6 0 0 4294967296,' flowid 1:1 action drop
tc filter replace dev lo ingress pref 1 handle 5 bpf bc '1,6 0 0 4294967296,' flowid 1:1 action pipe
tc filter replace dev lo ingress pref 1 bpf bc '1,6 0 0 4294967297,' flowid 1:1
tc filter show dev lo ingress

tc filter del dev lo ingress pref 1 handle 2 bpf
tc filter show dev lo ingress

tc filter add dev lo ingress prio 1 handle 2 bpf da obj /tmp/bpf.o
tc filter add dev lo ingress pref 2 bpf da obj /tmp/bpf.o
tc filter del dev lo ingress pref 1
tc filter show dev lo ingress

tc qdisc del dev lo clsact

pause
# tmp ebpf prog
cat <<EOF > /tmp/bpf.c
#include <linux/bpf.h>
#include <iproute2/bpf_elf.h>

#ifndef __section
# define __section(x) __attribute__((section(x), used))
#endif

static void (*tail_call)(void *ctx, void *map, int index) =
	(void *)BPF_FUNC_tail_call;

struct bpf_elf_map __section("maps") jmp = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

struct bpf_elf_map __section("maps") pmj = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.size_key	= sizeof(int),
	.size_value	= sizeof(int),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 1,
};

__section("classifier")
int x(struct __sk_buff *skb) {
	tail_call(skb, &jmp, 0);
	tail_call(skb, &pmj, 0);
	return -1;
}

__section("foo")
int y(struct __sk_buff *skb) {
	return 1;
}

__section("bar")
int z(struct __sk_buff *skb) {
	return 2;
}

char __license[] __section("license") = "GPL";
EOF

clang -O2 -Wall -target bpf -c /tmp/bpf.c -o /tmp/bpf.o

# ebpf graft
tc qdisc add dev lo clsact

tc filter add dev lo ingress bpf da obj /tmp/bpf.o
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o sec foo
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o sec bar
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o sec foo verb
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o type act sec foo # will fail
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o type who sec foo # will fail
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o type cls sec foo
tc exec bpf graft m:globals/pmj key 0 obj /tmp/bpf.o type cls

ls -la /sys/fs/bpf/tc/globals/

link /sys/fs/bpf/tc/globals/pmj /sys/fs/bpf/tc/globals/mmm
tc exec bpf graft m:globals/mmm key 0 obj /tmp/bpf.o sec bar

ln -s /sys/fs/bpf/tc/globals/pmj /sys/fs/bpf/tc/globals/aaa
tc exec bpf graft m:globals/aaa key 0 obj /tmp/bpf.o sec foo

tc qdisc del dev lo clsact

pause
# ebpf dbg

tc exec bpf dbg &
sleep 0
killall tc

tc exec bpf debug &
sleep 0
killall tc

pause
# ebpf import

tc qdisc add dev lo clsact

unlink /tmp/bpf.a 2> /dev/null
tc exec bpf import /tmp/bpf.a run env | grep BPF &
sleep 0
tc filter add dev lo ingress bpf da obj /tmp/bpf.o export /tmp/bpf.a

unlink /tmp/bpf.b 2> /dev/null
tc exec bpf import /tmp/bpf.b run ls -la /proc/self/fd/ | grep bpf &
sleep 0
tc filter add dev lo ingress bpf da obj /tmp/bpf.o export /tmp/bpf.b

tc qdisc del dev lo clsact
tc action flush action bpf

pause
# cls pinned

tc qdisc add dev lo clsact

./fds_example.cls -F /sys/fs/bpf/prog-cls-1 -P -p 2>/dev/null
./fds_example.cls -F /sys/fs/bpf/prog-cls-2 -P -p 2>/dev/null

tc filter add dev lo ingress bpf da fd /sys/fs/bpf/prog-cls-1
tc filter add dev lo ingress bpf da fd /sys/fs/bpf/prog-cls-2
tc filter add dev lo ingress bpf fd /sys/fs/bpf/prog-cls-2 action drop
tc filter show dev lo ingress

tc filter del dev lo ingress

tc filter add dev lo ingress bpf da obj /tmp/bpf.o
tc exec bpf graft m:globals/jmp key 0 fd /sys/fs/bpf/prog-cls-2
tc exec bpf graft m:globals/jmp key 0 fd /sys/fs/bpf/prog-cls-1
tc filter del dev lo ingress

tc filter add dev lo ingress bpf da pinned /sys/fs/bpf/prog-cls-1
tc filter add dev lo ingress bpf da object-pinned /sys/fs/bpf/prog-cls-1
tc filter show dev lo ingress

tc qdisc del dev lo clsact
tc action flush action bpf

pause
## action

umount /sys/fs/bpf/

# cbpf inline parsing
tc qdisc add dev lo clsact

tc action add action bpf bytecode '1,6 0 0 4294967295,'
tc action add action bpf bytecode '1,6 0 0 4294967297,'

tc action add action bpf bc '1,6 0 0 4294967298,' index 44
tc action del action bpf index 44
tc action add action bpf bc '1,6 0 0 4294967298,' index 44
tc action replace action bpf bc '1,6 0 0 4294967291,' index 44

tc action add action bpf bcf /tmp/bpf-asm.i
tc action add action bpf bc "`bpf_asm /tmp/bpf-asm.c`" index 55

tc action show action bpf

tc filter add dev lo ingress bpf bytecode '1,6 0 0 4294967295,' flowid 1:1 action bpf index 44
tc filter add dev lo egress  bpf bytecode '1,6 0 0 4294967295,' flowid 1:1 action bpf index 55 action bpf index 44 action drop

tc filter show dev lo ingress
tc filter show dev lo egress

tc qdisc del dev lo clsact
tc action flush action bpf

# ebpf object
pause

tc qdisc add dev lo clsact

tc filter add dev lo ingress bpf bytecode '1,6 0 0 4294967295,' flowid 1:1 \
   action bpf obj /tmp/bpf.o sec classifier
tc filter add dev lo ingress prio 1 handle 1 bpf bc '1,6 0 0 4294967295,' flowid 1:1 \
   action bpf obj /tmp/bpf.o sec classifier verb action drop
tc filter show dev lo ingress

tc action add action bpf obj /tmp/bpf.o sec foo verb index 66
tc action add action bpf obj /tmp/bpf.o sec bar index 77

tc filter replace dev lo ingress prio 1 handle 1 bpf bytecode '1,6 0 0 4294967294,' flowid 1:1 action bpf index 66 action bpf index 77

tc qdisc del dev lo clsact
tc action flush action bpf

# action graft

tc qdisc add dev lo clsact

tc action add action bpf obj /tmp/bpf.o sec classifier index 11
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o type act sec foo
tc exec bpf graft m:globals/jmp key 0 obj /tmp/bpf.o type act sec bar
tc exec bpf graft m:globals/jmp key 1 obj /tmp/bpf.o type act sec bar # will fail
tc filter replace dev lo ingress bpf bytecode '1,6 0 0 4294967294,' flowid 1:1 action bpf index 11
tc action show action bpf

tc qdisc del dev lo clsact
tc action flush action bpf

pause
# action exec

unlink /tmp/bpf.d 2> /dev/null
tc exec bpf import /tmp/bpf.d run env | grep BPF &
sleep 0
tc action add action bpf obj /tmp/bpf.o sec classifier export /tmp/bpf.d index 111

unlink /tmp/bpf.e 2> /dev/null
tc exec bpf import /tmp/bpf.e run ls -la /proc/self/fd/ | grep bpf &
sleep 0
tc action add action bpf obj /tmp/bpf.o sec classifier export /tmp/bpf.e index 222

tc action get action bpf index 111
tc action get action bpf index 222

tc action flush action bpf
tc action show action bpf

pause
# action pinned

./fds_example.act -F /sys/fs/bpf/prog-act-1 -P -p 2>/dev/null
./fds_example.act -F /sys/fs/bpf/prog-act-2 -P -p 2>/dev/null

tc action add action bpf pin /sys/fs/bpf/prog-act-1 index 33
tc action add action bpf pin /sys/fs/bpf/prog-act-2 index 44
tc action show action bpf

tc action flush action bpf

tc action add action bpf obj /tmp/bpf.o sec classifier index 11
tc exec bpf graft m:globals/jmp key 0 fd /sys/fs/bpf/prog-act-2 type act verb
tc exec bpf graft m:globals/jmp key 0 pin /sys/fs/bpf/prog-act-1 type act
tc exec bpf graft m:globals/jmp key 1 pin /sys/fs/bpf/prog-act-1 type act # will fail

tc action show action bpf
tc action flush action bpf
