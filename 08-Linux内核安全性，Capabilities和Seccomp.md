BPF是一种扩展内核功能的强有力的方法，具备安全和高性能的特点，而又不影响内核的稳定性。因此，内核开发人员认为，实现BPF程序（也称为Seccomp BPF）支持的Seccomp过滤器，然后利用该过滤器的丰富功能来改善Seccomp中的进程隔离是很好的。在本章中，我们研究什么是Seccomp以及如何使用它。然后，您将学习如何使用BPF程序编写Seccomp过滤器。之后，您将探索内核用于Linux安全模块的内置BPF挂钩。

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

Seccomp代表安全计算，它是在Linux内核中实现的安全层，允许开发人员筛选特定的syscall。尽管Seccomp可与Capabilities媲美，但与Capabilities相比，它控制特定系统调用的能力使其更加灵活。

Seccomp和Capabilites不是互斥的；它们经常一起使用，可以从两个角度给您带来好处。例如，您可能希望为进程提供CAP_NET_ADMIN功能，但通过阻塞accept和accept4系统调用的方式不允许它接受套接字上的连接。

Seccomp进行过滤的方式是基于使用SECCOMP_MODE_FIL TER模式的BPF过滤器，并且系统调用过滤的方式与对数据包的过滤方式相同。

通过PR_SET_SECCOMP操作使用prctl加载Seccomp筛选器；这些过滤器以BPF程序的形式表示，该程序在使用seccomp_data结构表示的每个Seccomp数据包上执行。该结构包含参考体系结构，系统调用时的CPU指令指针以及最多六个表示为uint64的系统调用参数。

从linux/seccomp.h 的内核源代码中看，seccomp_data结构的样子如下：

```c
    struct seccomp_data { 
            int nr;
            __u32 arch;
            __u64 instruction_pointer;
            __u64 args[6];
    };
```

通过该结构可以看出，我们可以基于syscall，基于其参数或基于它们的组合进行过滤。

接收到每个Seccomp数据包后，过滤器有责任进行处理以做出最终决定，以告知内核下一步该做什么。最终由他们的返回值（状态代码）决定，如下所述：

**SECCOMP_RET_KILL_PROCESS**

它会在过滤系统调用后立即终止整个进程，因此不会执行。

**SECCOMP_RET_KILL_THREAD**

过滤系统调用后，它将立即终止当前线程，因此不会执行。

**SECCOMP_RET_KILL**

这是 capability `SECCOMP_RET_KILL_THREAD` 的别名。

**SECCOMP_RET_TRAP**

系统调用被禁用，并且SIGSYS（错误系统调用）信号将发送到调用它的任务。

**SECCOMP_RET_ERRNO**

不会执行系统调用，并且过滤器返回值的SECCOMP_RET_DATA部分作为errno值传递到用户态。根据错误的原因，返回不同的errno。您可以在以下部分中找到错误编号列表。

**SECCOMP_RET_TRACE**

用于通知Ptrace追踪程序，该追踪程序使用PTRACE_O_TRACESECCOMP进行拦截，以在调用syscall时观察并控制syscall的执行。如果没有连接追踪器，则会返回错误，将errno设置为 -ENOSYS，并且不会执行系统调用。

**SECCOMP_RET_LOG**

允许并记录系统调用。

**SECCOMP_RET_ALLOW**

允许系统调用。

*ptrace是一个系统调用，用于在进程上实现称为追踪的追踪机制，从而能够观察和控制进程的执行。追踪程序可以有效地影响执行并更改追踪的存储寄存器。在Seccomp的上下文中，当由SECCOMP_RET_TRACE状态代码触发时，将使用ptrace。因此，追踪器可以防止系统调用执行并实现其自己的逻辑。*

### Seccomp Errors

有时，在使用Seccomp时，您会遇到由SECCOMP_RET_ERRNO类型的返回值给出的不同错误。要通知发生错误，seccomp syscall将返回-1而不是0。

可能的错误如下：

**EACCESS**

不允许调用者进行系统调用-通常是因为调用者没有CAP_SYS_ADMIN特权或没有使用prctl设置no_new_privs，这是我们会在本章稍后说明的。

**EFAULT**

传递的参数（seccomp_data结构中的args）没有有效的地址。

**EINVAL**

它可能代表了下面的意思：

- 请求的操作对于内核来说，是未知或是不支持的。
- 指定的标志对于请求的操作无效。
- 操作包含了BPF_ABS，但是指定的偏移量存在问题可能会超过seccomp_data结构的大小。
- 传递给过滤器的指令数量超过了最大数量限制。

**ENOMEM**

没有足够的内存来执行程序。

**EOPNOTSUPP**

该操作指定的action 可用于SEC COMP_GET_ACTION_AVAIL，但实际上内核不支持参数中的return 该action。

**ESRCH**

线程同步期间存在问题。

**ENOSYS**

SECCOMP_RET_TRACE action 没有附加追踪器。

*prctl是一个系统调用，它允许用户态程序控制（设置和获取）进程的特定方面，例如字节序，线程名称，安全计算（Seccomp）模式，特权，Perf事件等。*

Seccomp可能听起来像是沙盒机制，但事实并非如此。 Seccomp是一个实用程序，可让其用户开发沙箱机制。现在，这是使用Seccomp系统调用直接调用的过滤器编写程序来编写自定义交互的方法。

### Seccomp BPF 过滤器示例

在这个例子中，我们展示了如何将前面描述的两个动作放在一起：

- 根据其决策，编写Seccomp BPF程序以用作具有不同返回码的过滤器。
- 使用prctl加载过滤器。

首先，该示例需要标准库和Linux内核中的一些headers：

```c
    #include <errno.h>
    #include <linux/audit.h>
    #include <linux/bpf.h>
    #include <linux/filter.h>
    #include <linux/seccomp.h>
    #include <linux/unistd.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/prctl.h>
    #include <unistd.h>
```

在尝试执行此示例之前，我们需要确保已将CONFIG_SECCOMP和CONFIG_SECCOMP_FILTER设置为y来编译内核。在运行的计算机中，可以使用以下方法进行检查：

```sh
    cat /proc/config.gz| zcat | grep -i CONFIG_SECCOMP
```

其余代码是install_filter函数，由两部分组成。第一
部分包含我们的BPF过滤指令列表：

```c
static int install_filter(int nr, int arch, int error) { 
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))), BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))), BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
                BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
                BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      };
```

使用linux/filter.h 中定义的BPF_STMT和BPF_JUMP宏来设置指令。

让我们按照说明进行操作：

**BPF_STMT(BPF_LD + BPF_W + BPF_ABS (offsetof(struct seccomp_data, arch)))**

这将以BPF_W字的形式加载并累加BPF_LD，并且以固定的BPF_ABS偏移量包含数据包数据。

**BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3)**

这将使用BPF_JEQ检查累加器常中数BPF_K的值是否等于arch。如果是这样，它将以零偏移量跳到下一条指令。否则，它将以3个偏移量跳转以给出错误，在这种情况下，因为架构不匹配。

**BPF_STMT(BPF_LD + BPF_W + BPF_ABS (offsetof(struct seccomp_data, nr)))**

这会将系统调用号中的值与nr变量的值进行比较。如果它们相等，它将转到下一条指令并禁止syscall；否则，它将允许使用SECCOMP_RET_ALLOW的系统调用。

**BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SEC
COMP_RET_DATA))**

这将通过BPF_RET终止程序，结果是错误SEC COMP_RET_ERRNO，并带有来自err变量的指定错误号。

**BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)**

这将使用BPF_RET终止程序，并允许使用SECCOMP_RET_ALLOW的系统调用执行。

PS： 

    Seccomp 是 cBPF
    在这一点上，您可能想知道为什么使用指令列表来代替ELF对象或JIT编译后的C程序？

    有两个原因：

    1：首先是Seccomp使用cBPF（经典BPF）而不使用eBPF，这意味着它没有注册表，而只是一个累加器来存储最后的计算结果，如您在示例中所注意到的。

    2：第二个是Seccomp不直接接受BPF指令数组的指针。我们使用的宏只是以程序员友好的方式来指定那些指令的助手。

如果您需要进一步的帮助来理解该程序集，则可能会发现一些有用的伪代码，它们可以完成相同的操作：

```c
if (arch != AUDIT_ARCH_X86_64) { 
    return SECCOMP_RET_ALLOW;
}

if (nr == __NR_write) { 
    return SECCOMP_RET_ERRNO;
}
return SECCOMP_RET_ALLOW;
```

在socket_filter结构中定义了过滤器代码之后，我们需要定义一个sock_fprog，其中包含过滤器代码和过滤器本身的计算长度。需要此数据结构作为以后声明流程操作的参数：

```c
struct sock_fprog prog = {
.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter,
};
```

现在，在install_filter函数中只剩下一件事情要做：加载程序本身！为此，我们使用prctl并使用PR_SET_SECCOMP作为选项，因为我们要进入安全的计算模式。然后，我们指示该模式加载包含在sock_fprog类型的prog变量中的SECCOMP_MODE_FILTER过滤器。

```c
if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { 
    perror("prctl(PR_SET_SECCOMP)");
    return 1;
    }
    return 0; 
}

```

最后，我们可以利用install_filter函数，但是在使用它之前，我们需要使用prctl在当前执行中设置PR_SET_NO_NEW_PRIVS，以避免子进程具有比父进程更大的特权的情况。这使我们可以在没有root特权的情况下在install_filter函数中进行以下prctl调用。

现在我们可以调用install_filter函数。我们将阻止所有与X86-64体系结构相关的write syscall，并将拒绝所有尝试的权限。安装过滤器后，我们只需使用第一个参数继续执行：

```c
int main(int argc, char const *argv[]) {
if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        return 1; 
        }
        install_filter(__NR_write, AUDIT_ARCH_X86_64, EPERM);
        return system(argv[1]);
         }

```

现在我们实际联系一下。

要编译我们的程序，我们可以使用clang或gcc；无论哪种方式，这只是一个问题
没有特殊选项的main.c文件的编译：

```sh
clang main.c -o filter-write
```

我们说过，我们阻止了程序中的所有写入。为了对其进行测试，我们需要编写程序。 ls程序似乎是一个不错的选择，这是它正常运行的方式：

```sh
    ls -la
    total 36
    drwxr-xr-x 2 fntlnz users  4096 Apr 28 21:09 .
    drwxr-xr-x 4 fntlnz users  4096 Apr 26 13:01 ..
    -rwxr-xr-x 1 fntlnz users 16800 Apr 28 21:09 filter-write
    -rw-r--r-- 1 fntlnz users    19 Apr 28 21:09 .gitignore
    -rw-r--r-- 1 fntlnz users  1282 Apr 28 21:08 main.c
```

cool！这是我们包装程序使用情况的样子；我们只是将要测试的程序作为第一个参数传递：

```sh
./filter-write "ls -la"
```

执行后，该程序将输出完全空的内容，而没有任何输出。
但是，我们可以使用strace查看发生了什么：

```sh
strace -f ./filter-write "ls -la"
```

结果消除了很多噪音，其中的相关部分表明写入被EPERM错误阻止，这与我们设置的错误相同。这意味着该程序处于静默状态，因为它现在无法访问该系统调用：

```sh
[pid 25099] write(2, "ls: ", 4) = -1 EPERM (Operation not permitted) 
[pid 25099] write(2, "write error", 11) = -1 EPERM (Operation not permitted) 
[pid 25099] write(2, "\n", 1) = -1 EPERM (Operation not permitted)
```

现在，您已经了解了Seccomp BPF的工作方式，并很好地了解了如何使用它。但是，如果有一种方法可以使用eBPF代替cBPF来实现其功能，那不是很好吗？

在考虑eBPF程序时，大多数人认为您只是编写它们并使用root特权加载它们。尽管该说法通常是正确的，但是内核实现了一系列机制来保护各个级别的eBPF对象。这些机制称为BPF LSM 钩子。

### BPF LSM Hooks

为了提供对系统事件的架构独立控制，LSM实施了hook的概念。从技术上讲，hook调用类似于syscall。但是，与系统无关并与LSM框架集成使hook很有趣，因为它提供的抽象层可以方便使用，并且可以避免在不同架构上使用syscall时可能发生的那种麻烦。

在撰写本文时，内核有七个与BPF程序相关的hooks，而SELinux是唯一实现它们的树内LSM。

您可以在以下文件的内核源代码树中看到此文件：include/linux/security.h：

```c
extern int security_bpf(int cmd, union bpf_attr *attr, unsigned int size); 
extern int security_bpf_map(struct bpf_map *map, fmode_t fmode);
extern int security_bpf_prog(struct bpf_prog *prog);
extern int security_bpf_map_alloc(struct bpf_map *map);
extern void security_bpf_map_free(struct bpf_map *map); extern int security_bpf_prog_alloc(struct bpf_prog_aux *aux); 
extern void security_bpf_prog_free(struct bpf_prog_aux *aux);

```

这些hooks中的每个hook将在执行的不同阶段被调用：

**security_bpf**


对执行的BPF系统调用进行初始检查。

**security_bpf_map**

在内核返回映射文件描述符时进行检查。

**security_bpf_prog**

在内核返回eBPF程序的文件描述符时进行检查。

**security_bpf_map_alloc**

BPF映射中的安全字段是否初始化。

**security_bpf_map_free**

是否在BPF映射中清除安全字段。

**security_bpf_prog_alloc**


在BPF程序中是否对安全字段进行初始化。

**security_bpf_prog_free**

是否在BPF程序中清理安全字段。

既然我们已经了解了它们，那么很明显，LSM BPF hook背后的想法是，它们可以为eBPF对象提供按对象的保护，以确保
只有具有适当特权的用户才能对映射和程序进行操作。

### 结论

对于要保护的所有内容，都不能以通用的方式实现安全性。能够以不同的层和不同的方式保护系统很重要，并且不管您信不信，最好的保护系统的方法是用不同的视角堆叠不同的层，以免受到损害的层不会导致这种能力。访问整个系统。内核开发人员在为我们提供可以使用的一组不同层和交互点方面做得很好。我们的希望是让您对这些层是什么以及如何使用BPF程序与它们进行交互有一个很好的了解。