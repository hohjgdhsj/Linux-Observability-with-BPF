XDP是Linux网络数据路径中的一种安全，可编程，高性能，内核集成的数据包处理器，当NIC驱动程序接收到数据包时，它将执行BPF程序。这使XDP程序可以在最早的时间点做出有关接收到的数据包的决定（丢弃，修改或允许它）。

执行点并不是使XDP程序快速运行的唯一方面。以下几个方面也扮演了很重要的角色：

- 使用XDP进行数据包处理时，没有内存分配。
- XDP程序仅适用于线性，无碎片的数据包，并且具有数据包的开始和结束指针。
- 无法访问完整的数据包元数据，这就是为什么这种程序接收的输入上下文的类型为xdp_buff而不是您在第6章中遇到的sk_buff结构的原因。
- 因为它们是eBPF程序，所以XDP程序的执行时间有限，其结果是它们的使用在网络管道中具有一定的成本。

*xdp_buff结构用于将数据包上下文呈现给BPF程序，该程序使用XDP框架提供的直接数据包访问机制。将其视为sk_buff的“轻量级”版本。两者之间的区别在于sk_buff也可以保留，并允许您与数据包的元数据（原型，标记，类型）混合，这些元数据仅在网络管道的更高级别可用。 xdp_buff提早创建且不依赖于其他内核层的事实是使用XDP更快地获取和处理数据包的原因之一。另一个原因是，xdp_buff不像对使用sk_buff的程序类型那样保存对路由，流量控制钩子或其他类型的数据包元数据的引用。*

在谈论XDP时，重要的是要记住它不是内核旁路机制。它旨在与其他内核组件和内部Linux安全模型集成。

在本章中，我们将探讨XDP程序的特性，各种XDP程序以及如何编译和加载它们。此后，为了提供更多背景信息，我们讨论了它的实际用例。

### XDP 程序总览

本质上，XDP程序所做的接收到的数据包之后，然后编辑接收到的数据包的内容或仅返回结果码。结果码用于确定对数据包做什么操作。您可以丢弃数据包，可以将其发送到同一接口，也可以将其传递到其余的网络栈。此外，为了与网络栈合作，XDP程序可以推送和拉取数据包的报头。例如，如果当前内核不支持封装格式或协议，则XDP程序可以对其进行解封装或转换协议，然后将结果发送给内核进行处理。

但是，XDP和eBPF之间有什么关联？

事实证明，XDP程序是通过bpf syscall控制的，并使用程序类型`BPF_PROG_TYPE_XDP`进行加载。同样，驱动程序钩子执行BPF字节码。

编写XDP程序时要理解的一个重要概念是，它们将在其中运行的上下文也称为操作模式。

#### 操作模式

XDP具有三种操作模式，可以轻松地测试功能，供应商提供的定制硬件以及没有定制硬件的通用内核。让我们逐一介绍它们。

##### 原生XDP

这是默认模式。在这种模式下，XDP BPF程序直接在网络驱动程序的早期接收路径之外运行。使用此模式时，检查驱动程序是否支持它很重要。您可以通过对给定内核版本的源代码树执行以下命令来检查它：

```sh
    # Clone the linux-stable repository
    git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git\
    linux-stable
    # Checkout the tag for your current kernel version
    cd linux-stable
    git checkout tags/v4.18
    # Check the available drivers
    git grep -l XDP_SETUP_PROG drivers/
```

执行之后有如下输出：

```sh
    drivers/net/ethernet/broadcom/bnxt/bnxt_xdp.c
    drivers/net/ethernet/cavium/thunder/nicvf_main.c
    drivers/net/ethernet/intel/i40e/i40e_main.c
    drivers/net/ethernet/intel/ixgbe/ixgbe_main.c
    drivers/net/ethernet/intel/ixgbevf/ixgbevf_main.c
    drivers/net/ethernet/mellanox/mlx4/en_netdev.c
    drivers/net/ethernet/mellanox/mlx5/core/en_main.c
    drivers/net/ethernet/netronome/nfp/nfp_net_common.c
    drivers/net/ethernet/qlogic/qede/qede_filter.c
    drivers/net/netdevsim/bpf.c
    drivers/net/tun.c
    drivers/net/virtio_net.c
```

从我们可以看到，内核4.18支持以下内容：

- Broadcom NetXtreme-C/E 网络驱动程序bnxt。

- Cavium thunderx 驱动。

- Inteli40 驱动。

- Intel ixgbe 和 ixgvevf  驱动。

- Mellanox mlx4 和 mlx5 驱动。

- Netronome Network Flow Processor。

- QLogic qede NIC 驱动。

- TUN/TAP。

- Virtio。

了解了原生操作模式后，我们可以继续了解如何使用 offloaded XDP 由网卡直接处理XDP程序。

##### Offloaded XDP

在这种模式下，XDP BPF程序直接加载到NIC中，而不是在主机CPU上执行。通过将执行移出CPU，与本地XDP相比，此模式具有高性能的特点。

通过查找 XDP_SETUP_PROG_HW，我们可以重用刚刚克隆的内核源代码树，以检查4.18中的哪些NIC驱动程序支持硬件offload：

```sh
git grep -l XDP_SETUP_PROG_HW drivers/
```

然后应该可以看到类似下面的内容：

```sh
    include/linux/netdevice.h
    866:    XDP_SETUP_PROG_HW,
    net/core/dev.c
    8001:           xdp.command = XDP_SETUP_PROG_HW;
    drivers/net/netdevsim/bpf.c
    200:    if (bpf->command == XDP_SETUP_PROG_HW && !ns->bpf_xdpoffload_accept) {
    205:    if (bpf->command == XDP_SETUP_PROG_HW) {
    560:    case XDP_SETUP_PROG_HW:
    drivers/net/ethernet/netronome/nfp/nfp_net_common.c
    3476:   case XDP_SETUP_PROG_HW:

```

这表明 Netronome网络流处理器（nfp），这意味着它还可以通过支持硬件offload和原生XDP来在两种模式下运行。

现在，对您自己来说一个好问题是，当我没有网卡和驱动程序来尝试XDP程序时该怎么办？答案很简单，通用XDP！

##### 通用XDP

对于想要编写和运行XDP程序而又没有原生或offloaded的XDP功能的开发人员，这是一种测试模式。从内核版本4.12开始支持通用XDP。例如，您可以在所有设备上使用此模式-在后面的示例中，我们将使用此模式来展示XDP的功能，而无需购买特定的硬件。


但是，谁负责所有组件和操作模式之间的协调？继续下一节以了解有关分组处理器的信息。

#### 包处理器

XDP数据包处理器是使XDP数据包上可以执行BPF程序并协调它们与网络栈之间的交互的角色。数据包处理器是XDP程序的内核组件，当NIC呈现数据包时，它们直接处理接收（RX）队列上​​的数据包。它可确保数据包可读可写，并允许您以数据包处理器操作的形式附加后处理判决。原子程序更新和向程序包处理器的新程序加载可以在运行时完成，而不会因网络和相关流量而中断任何服务。在运行时，XDP可以在“繁忙轮询”模式下使用，从而使您可以保留将必须处理每个RX队列的CPU。这避免了上下文切换，并且无论IRQ关联如何，都可以在到达时立即进行数据包反应。 XDP可以使用的另一种模式是“中断驱动”模式，另一方面，它不保留CPU，而是指示充当事件介质的中断来通知CPU它必须在发生新事件时处理新事件。仍在进行正常处理。


在图7-1中，您可以在RX/TX，应用程序，数据包处理器和应用于其数据包的BPF程序之间的交互点中看到。

请注意，在图7-1中有一些正方形，前面有一个字符串，前面带有XDP_。这些是XDP结果代码，我们接下来将介绍。

![The packet processor](./images/The-packet-processor.jpg)

#### XDP 结果码 (包处理器操作)

包处理器对于包的处理结果，可以使用五个返回码之一来表示，然后可以告诉网络驱动程序如何处理该包。让我们深入研究包处理器执行的操作：

**Drop (XDP_DROP)**

丢弃数据包。这发生在驱动程序的最早的RX阶段。丢弃数据包仅意味着将其回收回到刚刚“到达”的RX环形队列中。对于拒绝服务（DoS）缓解用例而言，尽早丢弃数据包是关键。这样，丢弃的数据包将使用最少的CPU处理时间和功耗。

**Forward (XDP_TX)**

转发数据包。这可能在修改数据包之前或之后发生。转发数据包意味着将收到的数据包页面退回到它之前到达的同一NIC。

**Redirect (XDP_REDIRECT)**

与XDP_TX相似，它能够传输XDP数据包，但是它可以将数据包转发到另一个NIC或BPF cpumap中。对于BPF cpumap，在NIC的接收队列上为XDP服务的CPU可以继续这样做，并将数据包推送到远程CPU之后该包将被上层内核堆栈处理。这类似于XDP_PASS，但是具有XDP BPF程序可以继续为传入的高负载提供服务的能力，而不是暂时将工作花费在当前数据包上以推送到上层。

**Pass (XDP_PASS)**

将数据包传递到普通网络栈进行处理。这等效于没有XDP的默认数据包处理行为。这可以通过以下两种方式之一来完成：

- 正常接收， 分配元数据（sk_buff），将数据包接收到堆栈上，然后将数据包引导到另一个CPU进行处理。它允许到用户态的原始接口。这可能在数据包被修改之前或之后发生。

- 通用接收 offload（GRO）， 可以执行大数据包的接收并合并相同连接的数据包。 GRO处理后最终将数据包通过“正常接收”流。

**Code error (XDP_ABORTED)**

表示eBPF程序错误，并导致数据包被丢弃。函数程序不应该将它用作返回代码。例如，如果程序除以零，则将返回XDP_ABORTED。 XDP_ABORTED的值将始终为零。它通过trace_xdp_exception追踪点，可以对其进行额外监视以检测不良行为。

这些操作代码在linux/bpf.h头文件中表示如下：

```c
enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
```

由于XDP操作决定了不同的行为，并且是数据包处理器的内部机制，因此您可以查看图7-1的简化版本，其中仅着眼于返回操作（请参见图7-2）。

![XDP action codes](./images/XDP-action-codes.jpg)

关于XDP程序的一个有趣的事情是，您通常不需要编写加载程序来加载它们。通过ip命令实现的大多数Linux机器都有一个不错的加载程序。下一节将介绍如何使用它。

### XDP and iproute2 作为加载器

[iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/)中提供的ip命令可以充当前端，以加载编译为ELF文件的XDP程序，并完全支持映射，映射重定位，尾部调用和对象固定。

因为可以将XDP程序的加载表示为现有网络接口的配置，所以将加载程序实现为ip link命令的一部分，该命令是进行网络设备配置的命令。

加载XDP程序的语法很简单：

```sh
# ip link set dev eth0 xdp obj program.o sec mysection
```

让我们逐一分析此命令参数：

**ip**

调用ip命令。

**link**

配置网络接口。

**set**

改变设备属性。

**dev eth0**

指定我们要操作和加载XDP程序的网络设备。

**xdp obj program.o**

从名为program.o的ELF文件（对象）中加载XDP程序。该命令的xdp部分告诉系统在可用时使用原生驱动程序，否则回退到通用驱动程序。您可以通过使用更具体的选择器来强制使用模式或其他模式：

- xdpgeneric 代表去使用通用XDP。

- xdpdrv 代表去使用原生XDP。

- xdpoffload 代表去使用 offloaded XDP。

**sec mysection**

指定section名称mysection，其中包含要从ELF文件中使用的BPF程序；如果未指定，将使用名为prog的部分。如果程序中未指定任何section，则必须在ip调用中指定sec .text。

下面我们看一个具体的例子。

例子是：我们有一个系统，该系统的Web服务器的端口为8000，我们希望通过断开与该服务器的所有TCP连接的方式来阻止对其服务器公网NIC上的页面的任何访问。

我们首先需要的是Web服务器。如果您还没有一个，可以从python3开始。

```sh
$ python3 -m http.server
```
Web服务器启动后，其打开端口将使用ss显示在打开的套接字中。如您所见，Web服务器已绑定到任何接口*：8000，所以到目前为止，任何可以访问我们公共接口的外部调用者都可以看到其内容！

```sh
    $  ss -tulpn
    Netid  State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
    tcp    LISTEN     0      5      *:8000                *:*

```

*套接字统计信息（终端中的ss）是用于调查Linux中网络套接字的命令行实用程序。它实际上是netstat的现代版本，其用户体验类似于Netstat，这意味着您可以传递相同的参数并获得可比较的结果。*

此时，我们可以检查运行HTTP服务器的计算机上的网络接口：

```sh
    $ ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever inet6 ::1/128 scope host
           valid_lft forever preferred_lft forever
    2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 02:1e:30:9c:a3:c0 brd ff:ff:ff:ff:ff:ff
        inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
           valid_lft 84964sec preferred_lft 84964sec
        inet6 fe80::1e:30ff:fe9c:a3c0/64 scope link
           valid_lft forever preferred_lft forever
    3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 08:00:27:0d:15:7d brd ff:ff:ff:ff:ff:ff
        inet 192.168.33.11/24 brd 192.168.33.255 scope global enp0s8
           valid_lft forever preferred_lft forever
        inet6 fe80::a00:27ff:fe0d:157d/64 scope link
           valid_lft forever preferred_lft forever

```

请注意，该计算机具有三个接口，并且网络拓扑很简单：

**lo**

这只是内部通信的回环接口。


**enp0s3**

这是管理网络层；管理员将使用此界面连接到Web服务器以执行其操作。

**enp0s8**

这是向外部开放的接口，我们的Web服务器需要从该接口中隐藏。

现在，在加载任何XDP程序之前，我们可以从另一台可以访问其网络接口的服务器（在本例中为IPv4 192.168.33.11）中检查服务器上的开放端口。

您可以使用nmap来检查远程主机上打开的端口，如下所示：

```sh
    # nmap -sS 192.168.33.11
    Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-06 23:57 CEST
    Nmap scan report for 192.168.33.11
    Host is up (0.0034s latency).
    Not shown: 998 closed ports
    PORT     STATE SERVICE
    22/tcp   open  ssh
    8000/tcp open  http-alt
```

我们可以看到8000端口，此时我们需要阻止它！

*Network Mapper（nmap）是一种网络扫描程序，可以执行主机，服务，网络和端口发现以及操作系统检测。它的主要用例是安全审核和网络扫描。在扫描主机上的开放端口时，nmap将尝试指定（或完整）范围内的每个端口。*

我们的程序将包含一个名为program.c的源文件，因此，让我们看看我们需要编写什么。

它需要使用IPv4 iphdr和以太网帧ethhdr header结构，以及协议常量和其他结构。让我们引入所需的header.h文件，如下所示：

```c
    #include <linux/bpf.h>
    #include <linux/if_ether.h>
    #include <linux/in.h>
    #include <linux/ip.h>
```

引入所需的header.h之后，我们可以声明在上一章中已经遇到的SEC宏，该宏用于声明ELF属性。

```c
    #define SEC(NAME) __attribute__((section(NAME), used))
```

现在，我们可以声明程序myprogram的主要入口点及其ELF section名称mysection。我们的程序将xdp_md结构指针作为输入上下文，相当于驱动程序xdp_buff的BPF。通过将其用作上下文，然后定义接下来将使用的变量，例如数据指针，以太网和IP层结构。

```c
    SEC("mysection")
    int myprogram(struct xdp_md *ctx) {
        int ipsize = 0;
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end; struct ethhdr *eth = data;
        struct iphdr *ip;

```

由于数据包含以太网帧，因此我们现在可以从中提取IPv4层。我们还要检查在IPv4层上查找的偏移量是否不超过整个指针空间，以使静态验证程序保持满意状态。当超出地址空间时，我们只是丢弃数据包。

```c
    ipsize = sizeof(*eth);
    ip = data + ipsize;
    ipsize += sizeof(struct iphdr); if (data + ipsize > data_end) {
        return XDP_DROP; 
    }
```

现在，在完成所有验证和设置之后，我们可以为该程序实现真正的逻辑，该逻辑基本上丢弃每个TCP数据包，同时允许其他任何内容。

```c
    if (ip->protocol == IPPROTO_TCP) { 
        return XDP_DROP;
    }
        return XDP_PASS; 
    }

```

现在我们的程序已经完成，保存为program.c。

下一步是使用Clang从我们的程序中编译ELF文件program.o。因为BPF ELF二进制文件与平台无关，所以我们可以在目标计算机之外执行此编译步骤。

```c
    $ clang -O2 -target bpf -c program.c -o program.o
```

现在回到托管我们的Web服务器的机器上，我们终于可以使用带有设置命令的ip实用程序针对公共网络接口enp0s8加载program.o，如前所述：

```c
    # ip link set dev enp0s8 xdp obj program.o sec mysection
```

您可能会注意到，我们选择mysection部分作为程序的入口点。

在这个阶段，如果该命令返回的退出代码为零且没有错误，我们可以检查网络接口以查看程序是否已正确加载：

```sh
# ip a show enp0s8
    3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric/id:32
        qdisc fq_codel state UP group default qlen 1000
        link/ether 08:00:27:0d:15:7d brd ff:ff:ff:ff:ff:ff
        inet 192.168.33.11/24 brd 192.168.33.255 scope global enp0s8
           valid_lft forever preferred_lft forever
        inet6 fe80::a00:27ff:fe0d:157d/64 scope link
           valid_lft forever preferred_lft forever
```

如您所见，现在ip a的输出有了一个新的细节。在MTU之后，它显示
xdpgeneric/id：32，它显示了两个有趣的信息位：

- 该驱动已经使用了xdpgeneric。

- XDP程序的ID为32。

最后一步是验证加载的程序按照我们的期望执行。我们可以通过在外部计算机上再次执行nmap来观察端口8000不再可访问，从而验证这一点。

```sh
    # nmap -sS 192.168.33.11
    Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-07 01:07 CEST
    Nmap scan report for 192.168.33.11
    Host is up (0.00039s latency).
    Not shown: 998 closed ports
    PORT    STATE SERVICE
    22/tcp  open  ssh

```

验证其所有功能的另一项测试可以尝试通过浏览器或执行任何HTTP请求来访问该程序。将192.168.33.11定位为目标时，任何类型的测试都将失败。干得好，恭喜您加载了第一个XDP程序！


如果在计算机上执行了所有这些步骤，你想恢复到最开始的状态，您可以通过下面的命令分离刚刚的程序并关闭设备的XDP:

```sh
    # ip link set dev enp0s8 xdp off
```

非常棒！XDP程序看起来非常简单，不是吗？

至少当使用`iproute2`作为加载程序时，您可以跳过必须自己编写加载程序的部分。在此示例中，我们的重点是iproute2，它已经为XDP程序实现了加载程序。但是，这些程序实际上是BPF程序，因此即使有时iproute2可以方便使用，您也应始终记住可以使用BCC加载程序，如下一节所示，也可以直接使用bpf syscall。拥有自定义加载程序的优点是允许您管理程序的生命周期及其与用户态的交互。

### XDP 和 BCC

与其他任何BPF程序一样，可以使用BCC编译，加载和运行XDP程序。以下示例显示了一个XDP程序，该程序类似于我们用于iproute2的程序，但是具有一个由BCC制作的自定义用户态加载程序。在这种情况下，需要使用加载程序，因为我们还希望计算丢弃TCP数据包时遇到的数据包数量。

像以前一样，我们首先创建一个名为program.c的内核空间程序。

在iproute2示例中，我们的程序需要导入与BPF和协议相关的结构和函数定义所需的headers。在这里，我们进行相同的操作，但是我们还使用BPF_TABLE宏声明了BPF_MAP_TYPE_PERCPU_ARRAY类型的映射。该映射将为每个IP协议索引包含一个数据包计数器，这就是大小为256（IP规范仅包含256个值）的原因。我们要使用BPF_MAP_TYPE_PERCPU_ARRAY类型，因为这是一种可以在不锁定的情况下保证CPU级别的计数器原子性的类型：

```c
    #define KBUILD_MODNAME "program"
    #include <linux/bpf.h>
    #include <linux/in.h>
    #include <linux/ip.h>
    BPF_TABLE("percpu_array", uint32_t, long, packetcnt, 256);
```


之后，我们声明我们的主要函数myprogram，该函数将xdp_md结构作为参数。这需要包含的第一件事是以太网IPv4帧的变量声明：

```c
    int myprogram(struct xdp_md *ctx) {
        int ipsize = 0;
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end; struct ethhdr *eth = data;
        struct iphdr *ip; long *cnt;
        __u32 idx;
        
        ipsize = sizeof(*eth);
        ip = data + ipsize;
        ipsize += sizeof(struct iphdr);

```

完成所有变量声明并可以访问现在包含以太网帧的数据指针和带有IPv4数据包的ip指针后，我们可以检查内存空间是否超出范围。如果是，我们丢弃数据包。如果内存空间正常，我们提取协议并查找packetcnt数组，以获取变量idx中当前协议的数据包计数器的先前值。然后我们将计数器加一。处理完增量后，我们可以继续并检查协议是否为TCP。如果是的话，我们就直接毫不犹豫丢弃该数据包；否则，我们允许：

```c
    if (data + ipsize > data_end) { 
        return XDP_DROP;
    }
    idx = ip->protocol;
    cnt = packetcnt.lookup(&idx); 
    if (cnt) {
        *cnt += 1; 
    }
    if (ip->protocol == IPPROTO_TCP) { 
        return XDP_DROP;
    }
    return XDP_PASS; 
    }
```

现在我们开始写加载器：loader.py。

它由两部分组成：实际的加载逻辑和打印数据包的循环计数。

对于加载逻辑，我们通过读取文件program.c打开程序。通过load_func，我们指示bpf syscall使用程序类型BPF.XDP将myprogram函数用作“ main”，BPF.XDP代表BPF_PROG_TYPE_XDP程序类型。

加载后，我们可以使用get_table访问名为packetcnt的BPF映射。

PS：确保将设备变量从enp0s8更改为要使用的接口。

```c
    #!/usr/bin/python
    from bcc import BPF 
    import time
    import sys

    device = "enp0s8"
    b = BPF(src_file="program.c")
    fn = b.load_func("myprogram", BPF.XDP)
    b.attach_xdp(device, fn, 0)
    packetcnt = b.get_table("packetcnt")
```

我们需要编写的其余部分是实际循环，以打印出数据包计数。没有这个，我们的程序将已经能够丢弃数据包，但是我们想看看那里发生了什么。我们有两个循环。外循环获取键盘事件，并在有信号中断程序时终止。当外部循环中断时，将调用remove_xdp函数，并将接口从XDP程序中释放。

在外循环中，内循环负责从packetcnt映射中获取值，并以以下格式协议打印它们：counter pkt/s。

```python
    prev=[0]*256
    print("Printing packet counts per IP protocol-number, hit CTRL+C to stop")
    while 1:
        try:
            for k in packetcnt.keys():
                val = packetcnt.sum(k).value i = k.value
                if val:
                    delta = val - prev[i]
                    prev[i] = val
                    print("{}: {} pkt/s".format(i, delta))
            time.sleep(1)
        except KeyboardInterrupt:
            print("Removing filter from device") 
            break
    b.remove_xdp(device, 0)  
```

好！现在我们用root特权来执行加载程序的操作，简单测试一下程序功能。

```sh
    # python program.py
 ```

输出以下内容：

```sh
    Printing packet counts per IP protocol-number, hit CTRL+C to stop
    6: 10 pkt/s
    17: 3 pkt/s
    ^CRemoving filter from device

```

我们仅遇到两种类型的数据包：6代表TCP，17代表UDP。

此时，您的大脑可能会开始考虑使用XDP的想法和项目，这非常好！但是，与往常一样，在软件工程中，如果您想编写一个好的程序，那么首先编写测试（或至少编写测试）很重要！下一节将介绍如何对XDP程序进行单元测试。

### 测试XDP程序

### XDP使用场景

在使用XDP时，了解它已被全球各个组织使用场景案例肯定是有用的。这可以帮助您想象为什么在某些情况下使用XDP比其他技术（例如套接字过滤或流量控制）更好。

#### 监控

如今，大多数网络监视系统都是通过编写内核模块或通过从用户态访问proc文件来实现的。编写，分发和编译内核模块并不是每个人的任务。这是一个危险的操作。它们也不容易维护和调试。但是，替代方案可能更糟。为了获得相同的信息，例如在一秒钟内收到一张卡有多少个数据包，您需要打开文件并拆分文件，在本例中为/sys/class/net/eth0/statistics/rx_packets。这似乎是一个好主意，但是为了获得一些简单的信息，它需要大量的计算，因为在某些情况下使用开放的syscall并不节省资源。

因此，我们需要一种解决方案，使我们能够实现与内核模块类似的功能，而又不会损失性能。 XDP非常适合此操作，因为我们可以使用XDP程序发送要提取的数据到映射中。然后，加载器可以使用该映射，该加载器可以将度量标准存储到存储后端中，并对其应用算法或将结果绘制在图形中。

#### DDoS防御

能够在NIC级别查看数据包可确保在第一阶段就能拦截任何可能的数据包，此时系统无需足够的计算能力来了解数据包是否对系统有用。在典型情况下，bpf映射可以让XDP程序对来自特定源的数据包 XDP_DROP。通过分析另一个映射接收到的数据包，可以在用户态中生成该数据包列表。一旦流入XDP程序的数据包与列表中的元素匹配，直接丢弃数据包。数据包被丢弃，内核甚至不需要花费CPU周期来处理它。其结果是使攻击者的目标难以实现，因为在这种情况下，DDoS无法浪费任何昂贵的计算资源。

#### 负载均衡

XDP程序一个有趣的用例是负载平衡。但是，XDP只能在数据包到达的同一NIC上重新传输数据包。这意味着XDP并不是实现经典负载均衡器（负载均衡器位于所有服务器之前并将流量转发到它们）的最佳选择。但是，这并不意味着XDP不适用于此场景。如果我们将负载平衡从外部服务器移到为应用程序提供服务的同一台计算机上，您将立即看到如何使用其NIC来完成这项工作。

通过这种方式，我们可以创建一个分布式负载平衡器，其中承载应用程序的每台计算机都可以帮助将流量分散到适当的服务器。

#### 防火墙

人们想到Linux上的防火墙时，通常会想到iptables或网络过滤器。使用XDP，您可以直接在NIC或其驱动程序中以完全可编程的方式获得相同的功能。通常，防火墙是昂贵的计算机，它们位于网络栈的顶部或节点之间，以控制其通信状态。但是，当使用XDP时，很明显，因为XDP程序非常便宜且快速，所以我们可以将防火墙逻辑直接实现到节点的NIC中，而不用拥有专用的机器。一个常见的用例是拥有一个XDP加载器，该加载器通过使用远程过程调用API更改一组规则来控制映射。然后，将映射中的规则集动态传递给加载到每台特定计算机中的XDP程序，以控制它可以从哪里以及在什么情况下接收什么。

这种选择不仅可以降低防火墙的成本。它允许每个节点部署自己的防火墙级别，而无需依赖用户态软件或内核来执行此操作。当使用 offloaded XDP作为操作模式进行部署时，由于处理甚至不是由主节点CPU进行的，因此我们可以获得最大的优势。


### 结论

您现在拥有了出色的技能！我保证XDP将以完全不同的方式帮助您考虑网络流。在处理网络数据包时，必须依赖iptables之类的工具或其他用户态工具通常令人沮丧且缓慢。 XDP之所以有趣，是因为它具有直接的数据包处理功能，因此速度更快，而且您可以编写自己的逻辑来处理网络数据包。因为所有这些任意代码都可以与映射一起使用并与其他BPF程序进行交互。接一下来，你可能需要在实际场景中去探索。

下一章所讲和第6章中介绍的许多概念有很大联系。BPF可以根据给定的输入进行过滤数据包。不要忘记BPF中的F代表过滤器！