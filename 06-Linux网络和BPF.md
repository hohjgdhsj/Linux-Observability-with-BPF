从网络的角度来看，BPF程序有两个使用场景：数据包捕获和过滤。

这意味着用户态程序可以将过滤器附加到任何套接字，并从数据包提取信息，并允许/禁止/重定向某些种类的数据包。

本章的目的是说明BPF程序如何在Linux内核网络栈中网络数据路径的不同阶段与 Socket Buffer 数据结构进行交互。 我们将介绍两种常见类型的程序：

- 与sockets相关的程序类型。

- 基于BPF分类器实现流量控制的程序类型。

*Socket Buffer 结构（也称为SKB或sk_buff）在内核中用来处理每个发送或接收的数据包。通过阅读SKB，您可以传递或丢弃数据包并填充BPF映射，以创建有关当前流量的统计信息和流量度量。*

*另外，一些BPF程序允许您操作SKB，并通过扩展对最终数据包进行转换，以重定向它们或更改其基本结构。 例如，在仅IPv6的系统上，您可以编写一个程序，将所有接收到的数据包从IPv4转换为IPv6，这可以通过处理数据包的SKB来完成。*

理解我们编写的各种程序之间的差异以及不同的程序如何导致相同的结果是理解BPF的关键。在下一节中，我们将探讨在套接字级别进行过滤的两种方法：使用经典BPF筛选器，以及使用附加到套接字的eBPF程序。

### BPF 和包过滤

如前所述，在网络方面，BPF过滤器和eBPF程序是BPF程序的两个主要的使用场景；但是，最初BPF程序是数据包过滤的同义词。

数据包过滤仍然是最重要的场景之一，并已在Linux 3.19中从经典BPF（cBPF）扩展到现代eBPF，并在过滤程序类型BPF_PROG_TYPE_SOCKET_FILTER 中添加了与映射相关的功能。

过滤器主要可用于三种高级方案：

- 实时丢弃流量（例如，仅允许用户数据报协议[UDP]流量并丢弃其他任何内容）。

- 实时观察流入实时系统的一组经过过滤的数据包。

- 使用pcap格式，重放和分析实时系统中捕获的网络流量。

*术语pcap来自两个词的结合：数据包和捕获。 pcap格式被实现为特定域的API，用于在数据包捕获库（libpcap）的库中捕获数据包。当您要将在实时系统上捕获的一组数据包直接保存到文件中，以便以后使用一种可以读取以pcap格式导出的数据包流的工具将其分析时，此格式在调试场景中很有用。*

在以下各节中，我们展示两种不同的方法来应用BPF程序进行数据包过滤的概念。首先，我们展示如何使用通用且广泛使用的工具（如tcpdump）充当用作过滤器的BPF程序的高级接口。然后，我们继续使用BPF程序类型 BPF_PROG_TYPE_SOCKET_FILTER 编写和加载自己的程序。

#### tcpdump 和 BPF表达式

在谈论实时流量分析和观察时，几乎每个人都知道的命令行工具之一是tcpdump。本质上是libp cap的前端，它允许用户定义高级过滤表达式。 tcpdump的作用是从您选择的网络接口（或任何接口）读取数据包，然后将接收到的数据包的内容写入stdout或文件。数据包流可以使用pcap过滤器语法进行过滤。 pcap过滤器语法是一种DSL，用于通过一组表达式组成的高级表达式来过滤数据包，这些表达式通常比BPF汇编更容易记住。由于整个集合都可以在man 7 pcap-filter中找到，因此无法解释pcap过滤器语法中所有可能的原语和表达式，因此不在本章的讨论范围之内，但是我们通过一些示例使您可以理解其功能。

场景是，我们在一个Linux盒子中，该盒子在端口8080上公开了一个Web服务器。该Web服务器未记录接收到的请求，我们真的想知道它是否正在接收任何请求，以及这些请求如何流入其中，因为所提供的应用程序的客户抱怨浏览时无法获得任何响应产品页面。在这一点上，我们仅知道客户正在使用该Web服务器提供的Web应用程序连接到我们的产品页面之一，而且几乎总是发生这种情况，我们不知道是什么原因造成的，因为最终用户通常，不会尝试为您调试服务，很遗憾，我们没有在该系统中部署任何日志记录或错误报告策略，因此在调查问题时我们完全是盲目的。幸运的是，有一种工具可以帮助我们！它是tcpdump，可以告诉它仅过滤在系统中使用端口8080上的传输控制协议（TCP）的IPv4数据包。因此，我们将能够分析Web服务器的流量并了解什么是网络流量。错误的请求。

这是使用tcpdump进行过滤的命令：

```sh
    # tcpdump -n 'ip and tcp port 8080'
```

让我们看看这个命令发生了什么：

- -n 告诉tcpdump不要将地址转换为相应的名称，我们想查看源地址和目标地址。

- ip和tcp端口8080是tcpdump将用于过滤数据包的pcap过滤器表达式。 ip表示IPv4，是表示更复杂的过滤器的结合体，可以添加更多表达式以进行匹配，然后我们指定仅对使用tcp端口8080来自或到达端口8080的TCP数据包感兴趣。最好的过滤器应该是tcp dst端口8080，因为我们只对将8080作为目标端口的数据包感兴趣，而对来自它的数据包不感兴趣。

输出将是这样的（没有多余的部分，例如完整的TCP握手）：

```sh
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
        listening on wlp4s0, link-type EN10MB (Ethernet), capture size 262144 bytes
        12:04:29.593703 IP 192.168.1.249.44206 > 192.168.1.63.8080: Flags [P.],
        seq 1:325, ack 1, win 343,
        options [nop,nop,TS val 25580829 ecr 595195678],
    
    length 324: HTTP: GET / HTTP/1.1
        12:04:29.596073 IP 192.168.1.63.8080 > 192.168.1.249.44206: Flags [.],
        seq 1:1449, ack 325, win 507,
        options [nop,nop,TS val 595195731 ecr 25580829],
        length 1448: HTTP: HTTP/1.1 200 OK
        12:04:29.596139 IP 192.168.1.63.8080 > 192.168.1.249.44206: Flags [P.],
        seq 1449:2390, ack 325, win 507,
        options [nop,nop,TS val 595195731 ecr 25580829],
        length 941: HTTP
        12:04:46.242924 IP 192.168.1.249.44206 > 192.168.1.63.8080: Flags [P.],
        seq 660:996, ack 4779, win 388,
        options [nop,nop,TS val 25584934 ecr 595204802],
        length 336: HTTP: GET /api/products HTTP/1.1
        12:04:46.243594 IP 192.168.1.63.8080 > 192.168.1.249.44206: Flags [P.],
        seq 4779:4873, ack 996, win 503,
        options [nop,nop,TS val 595212378 ecr 25584934],
        length 94: HTTP: HTTP/1.1 500 Internal Server Error
        12:04:46.329245 IP 192.168.1.249.44234 > 192.168.1.63.8080: Flags [P.],
        seq 471:706, ack 4779, win 388,
        options [nop,nop,TS val 25585013 ecr 595205622],
        length 235: HTTP: GET /favicon.ico HTTP/1.1
        12:04:46.331659 IP 192.168.1.63.8080 > 192.168.1.249.44234: Flags [.],
        seq 4779:6227, ack 706, win 506,
        options [nop,nop,TS val 595212466 ecr 25585013],
        length 1448: HTTP: HTTP/1.1 200 OK
        12:04:46.331739 IP 192.168.1.63.8080 > 192.168.1.249.44234: Flags [P.],
        seq 6227:7168, ack 706, win 506,
        options [nop,nop,TS val 595212466 ecr 25585013],
        length 941: HTTP
```

现在情况已经清楚得多了！我们有一堆请求进展顺利，返回了200 OK状态代码，但在 /api/products 端点上还有一个带有500 Internal Server Error代码的请求。我们的客户是对的；我们在列出产品时遇到了问题！

此时，您可能会问自己，这些pcap过滤内容和tcpdump具有自己的语法，那么它们与BPF程序有什么关系？ Linux上的Pcap过滤器已编译为BPF程序！而且由于tcpdump使用pcap过滤器进行过滤，这意味着每次使用过滤器执行tcpdump时，实际上是在编译和加载BPF程序来过滤数据包。幸运的是，通过将-d标志传递给tcpdump，可以转储在使用指定过滤器时将加载的BPF指令：

```sh
    tcpdump  -d  'ip and tcp port 8080'
```

该过滤器与上一个示例中使用的过滤器相同，但是由于带有-d标志，因此现在的输出是一组BPF汇编指令。

具体输出如下：

```sh
    (000) ldh      [12]
    (001) jeq      #0x800
    (002) ldb      [23]
    (003) jeq      #0x6
    (004) ldh      [20]
    (005) jset     #0x1fff
    (006) ldxb     4*([14]&0xf)
    (007) ldh      [x + 14]
    (008) jeq      #0x1f90
    (009) ldh      [x + 16]
    (010) jeq      #0x1f90
    (011) ret      #262144
    (012) ret      #0
```

让我们分析一下它：

ldh [12]

（ld）从累加器的偏移量为12的位置开始加载16位（即以太类型字段），如图6-1所示。

jeq #0x800 jt 2 jf 12

（j）如果（eq）相等，则跳转；检查上一条指令的Ethertype值是否等于0x800（这是IPv4的标识符），如果为true（jt），则为跳转到2；如果为false（jf），则跳转到12。如果Internet协议是IPv4将继续执行下一个指令，否则它将跳转到末尾并返回零。

ldb [23]

将字节加载到（ldb）中，将从IP帧加载更高层的协议字段，该字段位于偏移23处--偏移23来自以太网第2层帧中标头的14个字节（请参见图6-1）和协议在IPv4标头中的位置，即第9位，因此14 + 9 = 23。

jeq #0x6 jt 4 jf 12

如果相等，则再次跳跃。在这种情况下，我们检查先前提取的协议为0x6，即TCP。如果是，则跳至下一条指令（4），或者转到末尾（12）——如果不是，则丢弃该数据包。

ldh [20]

这是另一条加载半字指令——在这种情况下，它是从IPv4标头加载数据包偏移量+片段偏移量的值。

jset #0x1fff jt 12 6

如果我们在片段偏移量中找到的任何数据为true，则此jset指令将跳至12；否则，跳至6，这是下一条指令。指令0x1fff之后的偏移量告诉jset指令仅查看数据的最后13个字节。 （展开后变为0001 1111 11111111。）

ldxb 4*([14]&0xf)

（ld）将x（b）装入x（x）。该指令会将IP标头长度的值加载到x中。


ldh [x + 14]

另一个加载半字指令将获得偏移量（x + 14）的值，即IP报头长度+ 14，这是数据包中源端口的位置。

jeq #0x1f90 jt 11 jf 9

如果（x + 14）处的值等于0x1f90（十进制为8080），这意味着源端口将为8080，继续到11或通过继续到9（如果为false）来检查目标端口是否在端口8080上。

ldh [x + 16]

这是另一个加载半字指令，它将获取偏移量（x + 16）的值，该值是数据包中目标端口的位置。

jeq #0x1f90 jt 11 jf 12

这是另一个相等的跳转，这次用于检查目的地是否为8080，转到11；如果不是，请执行12，丢弃该报文。

ret #262144

到达此指令后，将找到一个匹配项，从而返回匹配的捕捉长度。默认情况下，此值为262,144字节。可以使用tcpdump中的-s参数对其进行调整。

![Layer 2 Ethernet frame structure](./images/Ethernet-frame-structure.jpg)

这是“正确的”示例，因为正如我们在Web服务器中所说的那样，我们只需要考虑将8080作为目标而不是作为源的数据包，因此tcpdump过滤器可以将其指定为dst目标领域：

```sh
    tcpdump -d 'ip and tcp dst port 8080'
```

在这种情况下，转储的指令集与前面的示例相似，但是如您所见，它缺少将数据包与端口8080的源进行匹配的全部内容。实际上，没有ldh [x + 14]和相对jeq＃0x1f90 jt 11 jf 9。

```sh
    (000) ldh      [12]
    (001) jeq      #0x800           jt 2    jf 10
    (002) ldb      [23]
    (003) jeq      #0x6             jt 4   jf 10
    (004) ldh      [20]
    (005) jset     #0x1fff          jt 10   jf 6
    (006) ldxb     4*([14]&0xf)
    (007) ldh      [x + 16]
    (008) jeq      #0x1f90          jt 9   jf 10
    (009) ret      #262144
    (010) ret      #0
```

除了像我们分析tcpdump生成的程序集外，您可能还想编写自己的代码来过滤网络数据包。事实证明，在这种情况下，最大的挑战是实际调试代码的执行以确保其符合我们的期望。在这种情况下，内核源代码树中的 tools/bpf 中有一个名为bpf_dbg.c的工具，它实际上是一个调试器，可让您加载程序和pcap文件来逐步测试执行情况。

*tcpdump也可以直接从.pcap文件读取并对其应用BPF过滤器。*

#### 原始套接字的数据包筛选（BPF_PROG_TYPE_SOCKET_FILTER）

BPF_PROG_TYPE_SOCKET_FILTER程序类型允许您将BPF程序附加到套接字。它接收到的所有数据包都将以sk_buff结构的形式传递给程序，然后程序可以决定是否丢弃或允许它们。这种程序还具有访问和处理映射的能力。

让我们看一个示例，看看如何使用这种BPF程序。

我们的示例程序的目的是计算观察到的接口中流动的TCP，UDP和Internet控制消息协议（ICMP）数据包的数量。为此，我们需要以下内容：

- 可以查看数据包流向的BPF程序。

- 用于加载程序并将其附加到网络接口的代码。

- 用于编译程序并启动加载程序的脚本。

此时，我们可以用两种方式编写BPF程序：作为C代码，然后将其编译到ELF文件中，或直接作为BPF程序集。在此示例中，我们选择使用C代码来显示更高级别的抽象以及如何使用Clang编译程序。请务必注意，要制作此程序，我们使用的标头和帮助程序仅在Linux内核的源代码树中可用，因此首先要做的是使用Git获得它的副本。为避免差异，您可以签出我们用来制作此示例的相同提交SHA：

```sh
    export KERNEL_SRCTREE=/tmp/linux-stable
    git clone  git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
      $KERNEL_SRCTREE
    cd $KERNEL_SRCTREE
    git checkout 4b3c31c8d4dda4d70f3f24a165f3be99499e0328
```

*要包含BPF支持，您将需要clang> = 3.4.0和llvm> = 3.7.1。要在安装中验证对BPF的支持，可以使用命令llc -version查看是否具有BPF目标。*

现在您已经了解了套接字过滤，现在我们可以开始使用socket类型的BPF程序。

##### BPF 程序

BPF程序的主要职责是访问它收到的数据包。检查其协议是TCP，UDP还是ICMP，然后在找到的协议的特定键上的映射数组上增加计数器。

对于此程序，我们将利用加载机制，该机制使用位于内核源代码树的 samples/bpf/bpf_load.c 中的帮助程序来解析ELF文件。加载功能 load_bpf_file 能够识别某些特定的ELF section头 并将其与相应的程序类型相关联。该代码的外观如下：

```c
    bool is_socket = strncmp(event, "socket", 6) == 0;
    bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;
    bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;
    bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;
    bool is_raw_tracepoint = strncmp(event, "raw_tracepoint/", 15) == 0; 
    bool is_xdp = strncmp(event, "xdp", 3) == 0;
    bool is_perf_event = strncmp(event, "perf_event", 10) == 0;
    bool is_cgroup_skb = strncmp(event, "cgroup/skb", 10) == 0;
    bool is_cgroup_sk = strncmp(event, "cgroup/sock", 11) == 0;
    bool is_sockops = strncmp(event, "sockops", 7) == 0;
    bool is_sk_skb = strncmp(event, "sk_skb", 6) == 0;
    bool is_sk_msg = strncmp(event, "sk_msg", 6) == 0;

```

代码要做的第一件事是在section 头和内部变量之间创建关联-就像SEC（“ socket”）一样，我们将以bool is_socket = true结尾。

在同一文件的后面，我们看到一组if指令，这些指令在标题和实际prog_type之间创建关联，因此对于is_socket，我们以BPF_PROG_TYPE_SOCKET_FILTER结尾：

```c
    if (is_socket) {
        prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    } else if (is_kprobe || is_kretprobe) { 
        prog_type =     BPF_PROG_TYPE_KPROBE;
    } else if (is_tracepoint) {
        prog_type = BPF_PROG_TYPE_TRACEPOINT;
    } else if (is_raw_tracepoint) {
        prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
    } else if (is_xdp) {
        prog_type = BPF_PROG_TYPE_XDP;
    } else if (is_perf_event) {
        prog_type = BPF_PROG_TYPE_PERF_EVENT;
    } else if (is_cgroup_skb) {
        prog_type = BPF_PROG_TYPE_CGROUP_SKB;
    } else if (is_cgroup_sk) {
        prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
    } else if (is_sockops) {
        prog_type = BPF_PROG_TYPE_SOCK_OPS;
    } else if (is_sk_skb) {
        prog_type = BPF_PROG_TYPE_SK_SKB;
    } else if (is_sk_msg) {
        prog_type = BPF_PROG_TYPE_SK_MSG;
    }else{
        printf("Unknown event '%s'\n", event); return -1;
    }
```

很好，所以因为我们要编写一个BPF_PROG_TYPE_SOCKET_FILTER程序，所以我们需要指定一个SEC（“ socket”）作为我们函数的ELF头，它将作为BPF程序的入口点。

从该列表中可以看到，有多种与套接字和常规网络操作有关的程序类型。在本章中，我们将展示 BPF_PROG_TYPE_SOCKET_FILTER 的示例；但是，您可以在第2章中找到所有其他程序类型的定义。此外，在第7章中，我们将讨论程序类型为BPF_PROG_TYPE_XDP 的XDP程序。

因为我们要存储遇到的每个协议的数据包计数，所以我们需要创建一个密钥/值映射，其中协议是键，数据包计为值。为此，我们可以使用BPF_MAP_TYPE_ARRAY：

```c
    struct bpf_map_def SEC("maps") countmap = { 
        .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int), 
    .max_entries = 256,
    };
```