# ip6hole
eBPF based tool to drop IPv6 traffic

Overview
--------

ip6hole attaches XDP and tc programs to a specified network device. The XDP program drops ingress traffic and the tc program drops egress traffic. All programs and maps are pinned allowing devices/interfaces to be added or removed on the fly.

Dependencies
------------

Ubuntu/Debian:
```
# apt install clang libelf1 libelf-dev zlib1g-dev
```

RHEL/CentOS/Fedora:
```
# dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

Build
-----

### Initialize libbpf and bpftool submodules

When cloning the repository:
```
$ git clone --recurse-submodules https://github.com/lbirchler/ip6hole.git
```

If you have already cloned the repository:
```
$ git submodule update --init 
```

### Build ip6hole

To build only:
```
$ cd src
$ make
```

To build and install:
```
$ cd src
$ sudo make install
```

Usage
-----

```
Usage: ip6hole [OPTION...]
Drop IPv6 Traffic.

USAGE: ip6hole [-a DEV] [-A] [-r DEV] [-R] [-s] [-d]

  -a, --add=DEV              Add device
  -A, --add-all              Add all devices
  -d, --display              Display dropped IPv6 traffic
  -r, --remove=DEV           Remove device
  -R, --remove-all           Remove all devices
  -s, --status               Display devices dropping IPv6 traffic
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

### Examples

#### Drop IPv6 traffic on specific device:
```
# ip6hole -a ens18
```

#### Drop IPv6 traffic on all devices:
```
# ip6hole -A
```

#### Display devices currently dropping IPv6 traffic: 
```
# ip6hole -s
```
```
dev: 1 ingress prog id: 108 egress prog id: 106
dev: 2 ingress prog id: 108 egress prog id: 106
```

#### Display dropped IPv6 traffic:
```
# ip6hole -d
```
```
[2] UDP     INGRESS fe80::54fb:6523:f105:1143 > ff02::1:3, pkt_bytes 41
[2] UDP     INGRESS fe80::54fb:6523:f105:1143 > ff02::1:3, pkt_bytes 41
[2] UDP     INGRESS fe80::a55:31ff:fe6d:9892.5678 > ff02::1.5678, pkt_bytes 183
[2] UDP     INGRESS fe80::54fb:6523:f105:1143 > ff02::1:3, pkt_bytes 41
[2] UDP     INGRESS fe80::54fb:6523:f105:1143 > ff02::1:3, pkt_bytes 41
[2] ICMPV6  EGRESS  2605:ad80:20:3009:349f:b0ff:fee9:2795 > 2607:f8b0:4002:c2c::65, pkt_bytes 64
[2] ICMPV6  EGRESS  2605:ad80:20:3009:349f:b0ff:fee9:2795 > 2607:f8b0:4002:c2c::65, pkt_bytes 64
[2] ICMPV6  EGRESS  2605:ad80:20:3009:349f:b0ff:fee9:2795 > 2607:f8b0:4002:c2c::65, pkt_bytes 64
[2] ICMPV6  EGRESS  2605:ad80:20:3009:349f:b0ff:fee9:2795 > 2607:f8b0:4002:c2c::65, pkt_bytes 64
[2] ICMPV6  EGRESS  2605:ad80:20:3009:349f:b0ff:fee9:2795 > 2607:f8b0:4002:c2c::65, pkt_bytes 64
[2] ICMPV6  EGRESS  fe80::349f:b0ff:fee9:2795 > fe80::a55:31ff:fe6d:9892, pkt_bytes 32
[2] ICMPV6  EGRESS  fe80::349f:b0ff:fee9:2795 > fe80::a55:31ff:fe6d:9892, pkt_bytes 32
[2] ICMPV6  EGRESS  fe80::349f:b0ff:fee9:2795 > fe80::a55:31ff:fe6d:9892, pkt_bytes 32
...
```

#### Remove specific device (allow IPv6 traffic):
```
# ip6hole -r ens18
```

#### Remove all devices (allow all IPv6 traffic):
```
# ip6hole -R
```

note: `-R` will also unpin all programs and maps