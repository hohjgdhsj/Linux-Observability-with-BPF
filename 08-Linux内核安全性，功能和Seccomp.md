BPF是一种扩展内核功能的强有力的方法，具备安全和高性能的特点，而又不影响内核的稳定性。因此，内核开发人员认为，通过实现由BPF程序（也称为Seccomp BPF）支持的Seccomp过滤器来利用其多功能性来改善Seccomp中的进程隔离是很好的。在本章中，我们研究什么是Seccomp以及如何使用它。然后，您将学习如何使用BPF程序编写Seccomp过滤器。之后，您将探索内核用于Linux安全模块的内置BPF挂钩。

Linux安全模块（LSM）是一个框架，提供了一组功能，这些功能可用于以标准化方式实现不同的安全模型。 LSM可以直接在内核源代码树中使用，例如Apparmor，SELinux和Tomoyo。

我们首先讨论Linux功能。

### 功能

使用Linux功能的问题是，您需要向无特权的进程提供执行特定任务的权限，但是您不想为二进制文件赋予suid特权或以其他方式使该进程具有特权，因此您只需减少攻击面即可为流程赋予完成特定任务的特定能力。例如，如果您的应用程序需要打开一个特权端口（例如80），而不是以root身份启动进程，则只需为其赋予 `CAP_NET_BIND_SERVICE` 功能。

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


*capsh (capability shell wrapper) 是一种可以启动特殊功能集的工具。*

如前所述，在这种情况下，我们不授予完全的root权限，而只是通过允许cap_net_bind_service功能以及程序已经拥有的所有其他功能来允许特权端口的绑定。为此，我们可以使用capsh包装程序。

```sh
# capsh --caps='cap_net_bind_service+eip cap_setpcap,cap_setuid,cap_setgid+ep' \
        --keep=1 --user="nobody" \
        --addamb=cap_net_bind_service -- -c "./capabilities"
```

让我们分析一下该命令：

capsh

    We use capsh as wrapper.

--caps='cap_net_bind_service+eip cap_setpcap,cap_setuid,cap_setgid+ep'

    Because we need to change the user (we don’t want to run as root), we need to specify cap_net_bind_service and the capabilities to actually do the user ID change from root to nobody, namely, cap_setuid and cap_setgid.

--keep=1

    We want to keep the set capabilities when the switch from root is done.

--user="nobody"

    The end user running our program will be nobody.

--addamb=cap_net_bind_service

    We set ambient capabilities because those are cleared after switching from root.

-- -c "./capabilities"

    After everything, we just run our program.

