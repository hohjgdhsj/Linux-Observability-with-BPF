BPF是一种扩展内核功能的强有力的方法，具备安全和高性能的特点，而又不影响内核的稳定性。因此，内核开发人员认为，通过实现由BPF程序（也称为Seccomp BPF）支持的Seccomp过滤器来利用其多功能性来改善Seccomp中的进程隔离是很好的。在本章中，我们研究什么是Seccomp以及如何使用它。然后，您将学习如何使用BPF程序编写Seccomp过滤器。之后，您将探索内核用于Linux安全模块的内置BPF挂钩。

Linux安全模块（LSM）是一个框架，提供了一组功能，这些功能可用于以标准化方式实现不同的安全模型。 LSM可以直接在内核源代码树中使用，例如Apparmor，SELinux和Tomoyo。

我们首先讨论Linux capabilities 。

### Capabilities 

使用Linux capabilities 的问题是，您需要向无特权的进程提供执行特定任务的权限，但是您不想为二进制文件赋予suid特权或以其他方式使该进程具有特权，因此您只需减少攻击面即可为流程赋予完成特定任务的特定能力。例如，如果您的应用程序需要打开一个特权端口（例如80），而不是以root身份启动进程，则只需为其赋予 `CAP_NET_BIND_SERVICE` capability。

考虑以下名为main.go的Go程序：
```golang
package main
import (
    "net/http"
    "log"
)
func main() {
    log.Fatalf("%v", http.ListenAndServe(":80", nil))
}

```

该程序在特权端口80上为HTTPserver提供服务。

我们通常要做的是在使用以下代码编译之后直接运行该程序：

```sh
$ go build -o capabilities main.go
$ ./capabilities
```

但是，由于我们没有赋予root特权，因此该代码在绑定端口时将输出错误：

```sh
2019/04/25 23:17:06 listen tcp :80: bind: permission denied
exit status 1
```


*capsh (capability shell wrapper) 是一种可以启动具有特殊capabilities集Shell的工具。*

如前所述，在这种情况下，我们不授予完全的root权限，而只是通过允许cap_net_bind_service功能以及程序已经拥有的所有其他功能来允许特权端口的绑定。为此，我们可以使用capsh包装程序。

```sh
# capsh --caps='cap_net_bind_service+eip cap_setpcap,cap_setuid,cap_setgid+ep' \
        --keep=1 --user="nobody" \
        --addamb=cap_net_bind_service -- -c "./capabilities"
```

让我们分析一下该命令：

**capsh**

使用capsh.

**--caps='cap_net_bind_service+eip cap_setpcap,cap_setuid,cap_setgid+ep'**

因为我们需要更改用户（我们不想以root身份运行），所以我们需要设定cap_net_bind_service。并且实际执行用户ID从root更改为nobody，所以也需要设定cap_setuid和cap_setgid。

**--keep=1**

从root切换完成后，我们希望保留设置的capabilities。

--user="nobody"

运行我们程序的最终用户将是nobody。

**--addamb=cap_net_bind_service**

我们设置 ambient capabilities 因为从root切换后这些功能将被清除。

**-- -c "./capabilities"**

完成所有操作后，我们只需运行我们的程序。

*Ambient capabilities是一种特殊capability，当前程序使用execve()执行子程序时，这种capability能够被子程序集成。只有在环境中允许且可被继承的那些capabilities才可以是ambient capabilities。*

此时，您可能会问自己–caps选项中的功能之后 +eip 是什么。这些标志用于确定是否：

- 该capability需要激活（p）。

- 该capability可用（e）。

- 该capability可以由子进程（i）继承。

因为我们要使用cap_net_bind_service，所以需要将其设置为e；然后在命令中，我们启动了一个shell。然后启动了二进制文件，而我们需要使其成为i。最后，我们希望使用p激活该功能（不是因为我们更改了UID）。最后就是cap_net_bind_service + eip。

您可以使用ss进行验证；我们将格式化输出以使其适合该页面，但是它将显示绑定端口和用户ID不同于0，在本例中为65534：

```sh
    # ss -tulpn -e -H | cut -d' ' -f17-
    128    *:80    *:*
    users:(("capabilities",pid=30040,fd=3)) uid:65534 ino:11311579 sk:2c v6only:0
```

在本示例中，我们使用了capsh，但是您可以使用libcap来编写包装器；有关更多信息，请参见man 3 libcap。

在编写程序时，开发人员实际上并不真正预先知道程序在运行时所需的所有功能，这是很常见的。此外，在较新的版本中，这些功能可能会更改。

为了更好地了解我们程序所使用的功能，我们可以使用BCC提供的功能强大的工具，该工具在内核函数cap_capable上设置了一个kprobe：

```sh
    /usr/share/bcc/tools/capable
    TIME      UID    PID    TID    COMM             CAP  NAME                 AUDIT
    10:12:53  0      424    424    systemd-udevd    12   CAP_NET_ADMIN        1
    10:12:57  0      1103   1101   timesync         25   CAP_SYS_TIME         1
    10:12:57  0      19545  19545  capabilities     10   CAP_NET_BIND_SERVICE 1
```

我们可以通过在cap_capable内核函数上使用带有单线kprobe的bpftrace来完成相同的操作：

```sh
bpftrace -e \ 
    'kprobe:cap_capable {
        time("%H:%M:%S  ");
        printf("%-6d %-6d %-16s %-4d %d\n", uid, pid, comm, arg2, arg3); 
    }'\
    | grep -i capabilities
```

如果启动了我们的程序capabilities，在kprobe之后则将输出类似以下内容的内容：

```sh
    12:01:56  1000   13524  capabilities     21   0
    12:01:56  1000   13524  capabilities     21   0
    12:01:56  1000   13524  capabilities     21   0
    12:01:56  1000   13524  capabilities     12   0
    12:01:56  1000   13524  capabilities     12   0
    12:01:56  1000   13524  capabilities     12   0
    12:01:56  1000   13524  capabilities     12   0
    12:01:56  1000   13524  capabilities     10   1
```

第五列是进程所需的capabilities，并且由于此输出还包括非审核事件，因此我们会看到所有非审核检查，最后看到所需的capabilities，并且审核标志（上一个输出中的最后一个）设置为1。感兴趣的是CAP_NET_BIND_SERVICE，它在内核源代码中的include/uapi/linux/capability.h 中定义为常量，并且具有ID 10：

```c
    /* Allows binding to TCP/UDP sockets below 1024 */
    /* Allows binding to ATM VCIs below 32 */
    
    #define CAP_NET_BIND_SERVICE 10
```

Capabilities通常在容器运行时（例如runC或Docker）中使用，以使容器没有特权，并仅允许运行大多数应用程序所需的capabilities。当应用程序需要特定capabilities时，在Docker中可以使用--cap-add完成：

```sh
docker run -it --rm --cap-add=NET_ADMIN ubuntu ip link add dummy0 type dummy
```

此命令将为该容器提供CAP_NET_ADMIN功能，从而使其能够
设置一个网络链接以添加dummy0接口。

一节将说明如何通过使用
另一种技术可以让我们以编程方式实现自己的过滤器。

### Seccomp



