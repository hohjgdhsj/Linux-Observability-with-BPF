通过传递消息来调用一个程序中的行为是软件工程中广泛使用的技术。一个程序可以通过发送消息来修改另一个程序的行为，这也允许在这些程序之间交换信息。 BPF最令人着迷的方面之一是，内核上运行的代码和加载了该代码的程序可以在运行时使用消息传递相互通信。

在这一章中，我们介绍了BPF程序和用户态程序如何相互通信。我们描述了内核和用户态之间不同的通信渠道，以及它们如何存储信息。我们还将向您展示这些通道的用例，以及如何使这些通道中的数据在程序初始化之间保持不变。

BPF映射是驻留在内核中的键/值存储。任何BPF程序都可以访问它们。在用户态中运行的程序也可以使用文件描述符访问这些映射。只要事先正确指定数据大小，就可以在映射中存储任何类型的数据。内核将键和值视为二进制 blobs，它并不关心您在映射中保留的内容。

BPF验证程序包括多种保护措施，以确保您创建和访问映射的方式是安全的。当我们解释如何访问这些映射中的数据时，我们也将解释这些保护措施。

### 创建 BPF 映射

创建BPF映射的最直接方法是使用bpf syscall。当调用中的第一个参数是BPF_MAP_CREATE时，您将告诉内核您要创建一个新映射。此调用将返回与您刚创建的映射关联的文件描述符标识符。 syscall中的第二个参数是此映射的配置：

```c
    union bpf_attr {
        struct {
            __u32 map_type;     /* one of the values from bpf_map_type */
            __u32 key_size;     /* size of the keys, in bytes */
            __u32 value_size;   /* size of the values, in bytes */
            __u32 max_entries;  /* maximum number of entries in the map */ 
            __u32 map_flags;    /* flags to modify how we create the map */
        };
    }
```

syscall中的第三个参数是此配置属性的大小。


例如，您可以创建一个哈希表映射来存储无符号整数作为键和值，如下所示：

```c
    union bpf_attr my_map { 
        .map_type = BPF_MAP_TYPE_HASH, 
        .key_size = sizeof(int), 
        .value_size = sizeof(int), 
        .max_entries = 100,
        .map_flags = BPF_F_NO_PREALLOC,
    };

    int fd = bpf(BPF_MAP_CREATE, &my_map, sizeof(my_map));
```

如果调用失败，则内核返回值-1。失败的原因可能有三个。如果其中一个属性无效，则内核将errno变量设置为EINVAL。如果执行该操作的用户没有足够的特权，则内核将errno变量设置为EPERM。最后，如果没有足够的内存来存储映射，则内核将errno变量设置为ENOMEM。

在以下各节中，我们将通过不同的示例指导您，向您展示如何使用BPF映射执行更高级的操作。让我们从一种更直接的方式开始创建任何类型的映射。

#### ELF创建BPF映射的约定

内核包括一些约定和帮助程序，用于生成和使用BPF映射。与直接执行系统调用相比，您可能会发现这些约定的出现频率更高，因为它们更具可读性且易于遵循。请记住，即使直接在内核中运行，这些约定仍会使用bpf syscall来创建映射，如果您事先不知道要使用哪种映射，则直接使用syscall会更有用。

帮助程序函数 bpf_map_create 封装了您刚刚看到的代码，从而使按需初始化映射更加容易。我们可以使用它仅用一行代码来创建先前的映射：

```c

    int fd;
    fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100,
            BPF_F_NO_PREALOC);

```

如果知道程序中需要哪种映射，也可以预先定义。这对于增加程序中使用的映射的可见性有很大帮助：

```c
    struct bpf_map_def SEC("maps") my_map = { 
        .type = BPF_MAP_TYPE_HASH, 
        .key_size = sizeof(int), 
        .value_size = sizeof(int), 
        .max_entries = 100,
        .map_flags =BPF_F_NO_PREALLOC, 
    };
```

以这种方式定义映射时，您使用的是 "section" 属性，在本例中为SEC("maps")。该宏告诉内核此结构是BPF映射，应该相应地创建它。

您可能已经注意到，在这个新示例中，我们没有与映射关联的文件描述符标识符。在这种情况下，内核使用名为map_data的全局变量将有关映射的信息存储在程序中。此变量是一个结构数组，根据您在代码中指定每个映射的方式进行排序。例如，如果先前的映射是代码中指定的第一个映射，则可以从数组的第一个元素获取文件描述符标识符：

```c
    fd = map_data[0].fd;
```

您还可以从此结构访问映射的名称及其定义；此信息
有时对于调试和追踪的目的很有用。

初始化映射后，可以开始在内核和用户态之间使用它们发送消息。现在，让我们看看如何使用这些映射存储的数据。

### 使用 BPF 映射

内核和用户态之间的通信将成为您编写的每个BPF程序的基本组成部分。当您为内核编写代码时，与为用户态程序编写代码时，访问映射的API不同。本节介绍每种实现的语义和特定细节。

#### 更新 BPF 映射中的元素

创建完任何映射后，您可能要做的第一件事就是向其中填充信息。内核助手为此提供了函数 bpf_map_update_elem。如果在内核运行的程序中从bpf/bpf_helpers.h 加载该函数，则与在用户态运行的程序中从 tools/lib/bpf/bpf.h 加载该函数的签名不同。这是因为您在内核中工作时可以直接访问映射，但是在用户态中工作时可以使用文件描述符来引用它们。它的行为也略有不同。在内核上运行的代码可以直接访问内存中的映射，并且将能够原子地就地更新元素。但是，在用户态中运行的代码必须将消息发送到内核，内核会在更新映射之前复制提供的值；这使得更新操作不是原子的。该函数在操作成功时返回0，在操作失败时返回负数。如果发生失败，则用失败原因填充全局变量errno。接下来，我们将在本章详细罗列出失败案例。

内核中的 bpf_map_update_elem 函数采用四个参数。第一个是指向我们已经定义的映射的指针。第二个是指向我们要更新的元素的Key的指针。由于内核不知道我们要更新的Key的类型，因此此方法定义为指向void的不透明指针，这意味着我们可以传递任何数据。第三个参数是我们要插入的值。此变量的使用与Key变量的使用相同。在本书中，我们将展示一些高级示例，说明如何利用不透明指针。您可以在此函数中使用第四个参数来更改映射的更新方式。此参数可以采用三个值：

- 如果您传递0，则表示内核要更新元素（如果存在），或者如果不存在则应在映射中创建该元素。

- 如果传递1，则告诉内核仅在元素不存在时才创建它。

- 如果传递2，则内核仅在元素存在时才对其进行更新。

这些值被定义为常量，您也可以使用它们，而不必记住整数语义。值如下：BPF_ANY表示0，BPF_NOEX IST表示1，BPF_EXIST表示2。

让我们使用上一节中定义的映射来编写一些示例。在第一个示例中，我们向映射添加了一个新值。由于映射为空，因此我们可以假设任何更新行为对我们都有利：

```c
    int key, value, result; 
    key = 1, value = 1234;

    result = bpf_map_update_elem(&my_map, &key, &value, BPF_ANY); if (result == 0)
        printf("Map updated with new element\n"); 
    else
        printf("Failed to update map with new value: %d (%s)\n", result, strerror(errno));

```

在此示例中，我们使用strerror来描述errno变量中设置的错误。您可以使用man strerror在手册页上了解有关此函数的更多信息。

现在，让我们看看尝试创建具有相同键的元素时得到的结果：

```c
    int key, value, result; 
    key = 1, value = 5678;

    result = bpf_map_update_elem(&my_map, &key, &value, BPF_NOEXIST); if (result == 0)
        printf("Map updated with new element\n"); 
    else
        printf("Failed to update map with new value: %d (%s)\n", result, strerror(errno));
```

因为我们已经在映射中创建了一个键为1的元素，所以调用bpf_map_update_elem的结果将为-1，而errno的值为EEXIST。该程序将在屏幕上打印以下内容：

```sh
    Failed to update map with new value: -1 (File exists)
```

同样，让我们​​更改此程序以尝试更新尚不存在的元素：

```c
    int key, value, result; 
    key = 1234, value = 5678;

    result = bpf_map_update_elem(&my_map, &key, &value, BPF_EXIST); if (result == 0)
        printf("Map updated with new element\n"); 
    else
        printf("Failed to update map with new value: %d (%s)\n", result, strerror(errno));
```

使用标志BPF_EXIST，此操作的结果将再次为-1。内核会将errno变量设置为ENOENT，程序将打印以下内容：

```sh
Failed to update map with new value: -1 (No such file or directory)
```

这些示例说明了如何从内核程序中更新映射。您也可以从用户态程序中更新映射。唯一的区别是他们使用文件描述符访问映射，而不是直接使用指向映射的指针。您还记得，用户态程序始终使用文件描述符访问映射。因此，在我们的示例中，我们将参数my_map替换为全局文件描述符标识符 map_data[0].fd。在这种情况下，原始代码如下所示：

```c
    int key, value, result; 
    key = 1, value = 5678;

    result = bpf_map_update_elem(map_data[0].fd, &key, &value, BPF_ANY)); if (result == 0)
        printf("Map updated with new element\n"); 
    else
        printf("Failed to update map with new value: %d (%s)\n", result, strerror(errno));
```
尽管在映射中存储的信息类型与您正在使用的映射类型有直接的关系，但是填充信息的方法将保持不变，就像在上一个示例中看到的那样。稍后我们将讨论每种映射类型可接受的键和值的类型；首先，我们来看看如何操作存储的数据。

#### 从 BPF 映射中读取元素

现在，我们在映射中填充了新元素，我们可以在代码中读取它们。在学习了bpf_map_update_element之后，读取的API看起来会很熟悉。

BPF还提供了两个不同的帮助程序，它们可以根据您的代码在哪里运行来从映射中读取。这两个帮助程序都称为 bpf_map_lookup_elem。像更新帮助程序一样，它们的第一个参数有所不同。内核方法引用了映射，而用户态帮助程序则将映射的文件描述符标识符作为其第一个参数。就像更新帮助程序一样，这两种方法都返回一个整数来表示操作是成功还是失败。这些帮助程序中的第三个参数是指向代码中变量的指针，该变量将存储从映射读取的值。我们根据您在上一节中看到的代码提供两个示例。

第一个示例读取BPF程序在内核上运行时插入映射中的值：

```c
   int key, value, result; 
    key = 1;

    result = bpf_map_lookup_elem(&my_map, &key, &value); 
    if (result == 0)
        printf("Value read from the map: '%d'\n", value);
    else
        printf("Failed to read value from the map: %d (%s)\n", result, strerror(errno));
```

我们尝试使用 bpf_map_lookup_elem 读取的某键的值，如果返回负数，它将在errno变量中设置错误。例如，如果我们在尝试读取值之前未插入该值，则内核将返回“not found”错误ENOENT。

第二个示例与您刚刚看到的示例类似，但是这次我们从用户态中运行的程序中读取映射：

```c
   int key, value, result; 
    key = 1;

    result = bpf_map_lookup_elem(map_data[0].fd, &key, &value); 
    if (result == 0)
        printf("Value read from the map: '%d'\n", value);
    else
        printf("Failed to read value from the map: %d (%s)\n", result, strerror(errno));
```
如您所见，我们已将 bpf_map_lookup_elem 中的第一个参数替换为映射的文件描述符标识符。帮助程序的行为与前面的示例相同。

这就是我们能够访问BPF映射中的信息所需要的。在后面的章节中，我们将研究如何通过不同的工具包简化该过程，以使访问数据更加简单。接下来，我们要讨论从映射中删除数据。

#### 从 BPF 映射中删除元素

我们可以在映射上执行的第三项操作是删除元素。与读写元素一样，BPF为我们提供了两个不同的帮助程序来删除元素，它们都称为bpf_map_delete_element。就像前面的示例一样，当您在内核上运行的程序中使用这些帮助程序时，它们会使用对映射的直接引用；在您在用户态上运行的程序中使用它们时，它们将使用映射的文件描述符标识符。

第一个示例删除了在内核上运行BPF程序时插入映射中的值：


```c
    int key, result; 
    key=1;

    result = bpf_map_delete_element(&my_map, &key); 
    if (result == 0)
        printf("Element deleted from the map\n"); 
        else
        printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));

```
如果您要删除的元素不存在，则内核返回负数。在这种情况下，它还会用“not found”错误ENOENT填充errno变量。

第二个示例在BPF程序在用户态上运行时删除该值：

```c
    int key, result; 
    key=1;

    result = bpf_map_delete_element(map_data[0].fd, &key); 
    if (result == 0)
        printf("Element deleted from the map\n"); 
        else
        printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));

```

您会看到我们再次更改了第一个参数以使用文件描述符标识符。它的行为将与内核的帮助程序保持一致。

到此为止，可以认为是BPF映射的创建/读取/更新/删除（CRUD）操作。内核提供了一些其他功能来帮助您进行其他常见操作。我们将在接下来的两个部分中讨论其中的一些。

#### 迭代BPF映射中的元素

我们在本节中讨论的最终操作可以帮助您在BPF程序中查找任意元素。在某些情况下，您可能不完全知道要查找的元素的键，或者只是想查看映射内的内容。 BPF为此提供了一条名为 bpf_map_get_next_key 的指令。与您迄今为止看到的帮助程序不同，此说明仅适用于在用户态上运行的程序。

该帮助程序为您提供了确定性的方式来遍历映射上的元素，但与大多数编程语言中的迭代器相比，其行为不那么直观。它需要三个参数。第一个是映射的文件描述符标识符，就像您已经看到的其他用户态帮助程序一样。接下来的两个参数是棘手的地方。根据官方文档，第二个参数key是您要查找的标识符，第三个参数next_key是映射中的下一个键。我们更喜欢将第一个参数称为lookup_key，为什么会在第二个参数中变得显而易见。当您调用此帮助程序时，BPF会尝试使用您传递的键作为查找键在此映射中查找元素；然后，它将next_key参数与映射中的相邻键一起设置。因此，如果您想知道哪个键位于键1之后，则需要将1设置为您的查找键，并且如果映射具有与此键相邻的键，则BPF会将其设置为next_key参数的值。

在示例中查看 bpf_map_get_next_key 的工作方式之前，让我们向映射添加更多元素：

```c
    int new_key, new_value, it; 

    for(it=2;it<6;it++){
        new_key = it;
        new_value = 1234 + it;
        bpf_map_update_elem(map_data[0].fd, &new_key, &new_value, BPF_NOEXIST);
    }

```

如果要打印映射中的所有值，可以将 bpf_map_get_next_key 与映射中不存在的查找键一起使用。这迫使BPF从映射的开头开始：

```c
    int next_key, lookup_key; 
    lookup_key = -1;

    while(bpf_map_get_next_key(map_data[0].fd, &lookup_key, &next_key) == 0) { 
        printf("The next key in the map is: '%d'\n", next_key);
        lookup_key = next_key;
    }
```

打印的结果应该如下：

```sh
    The next key in the map is: '1'
    The next key in the map is: '2'
    The next key in the map is: '3'
    The next key in the map is: '4'
    The next key in the map is: '5'
```

可以看到，在循环结束时，我们正在将下一个键分配给lookup_key。这样，我们将继续遍历映射，直到到达终点为止。当bpf_map_get_next_key 到达映射的末尾时，返回的值为负数，并且errno变量设置为ENOENT。这将中止循环执行。

可以想象，bpf_map_get_next_key 可以查找从映射中任何一点开始的键；如果您只想将下一个键用于另一个特定键，则无需从映射的开头开始。

bpf_map_get_next_key 可以在您身上发挥的作用还不止于此；您需要注意另一种行为。许多编程语言在映射中迭代其元素时会拷贝元素。如果程序中的某些其他代码决定对映射进行改变，则可以防止未知行为。如果该代码从映射中删除了元素，则尤其危险。 BPF不会在使用 bpf_map_get_next_key 对其进行循环之前拷贝映射中的值。如果程序的另一部分在遍历值时从映射上删除了一个元素，则bpf_map_get_next_key将在尝试为已删除的元素键找到下一个值时重新开始。让我们看一个例子：

```c
    int next_key, lookup_key; 
    lookup_key = -1;

    while(bpf_map_get_next_key(map_data[0].fd, &lookup_key, &next_key) == 0) { 
        printf("The next key in the map is: '%d'\n", next_key);

        if (next_key == 2) {
            printf("Deleting key '2'\n");
            bpf_map_delete_element(map_data[0].fd &next_key);
        }

        lookup_key = next_key;
    }
```

程序输出如下：

```sh
    The next key in the map is: '1'
    The next key in the map is: '2'
    Deleteing key '2'
    The next key in the map is: '1'
    The next key in the map is: '3'
    The next key in the map is: '4'
    The next key in the map is: '5'
```

此行为不是很符合直觉，因此在使用 bpf_map_get_next_key 时请记住这一点。

因为我们在本章中介绍的大多数映射类型的行为都类似于数组，所以要访问它们存储的信息时，对其进行迭代将是一项关键操作。但是，还有其他一些访问数据的功能，如下所示。

#### 查找并删除元素

内核提供给映射使用的另一个有趣函数是 bpf_map_lookup_and_delete_elem 。此功能在映射中搜索给定键，并从中删除元素。同时，它将元素的值写入变量以供程序使用。当您使用队列映射和堆栈映射时，此功能会派上用场，这将在下一节中介绍。但是，不仅限于仅用于这些类型的映射。让我们看一下如何在之前的示例中使用的映射中使用它的示例：

```c
    int key, value, result, it; 
    key=1;

    for(it=0;it<2;it++){
        result = bpf_map_lookup_and_delete_element(map_data[0].fd, &key, &value); 
        if (result == 0)
            printf("Value read from the map: '%d'\n", value); 
        else
            printf("Failed to read value from the map: %d (%s)\n", result, strerror(errno));
    }

```

在此示例中，我们尝试两次从映射中提取相同的元素。在第一次迭代中，此代码将在映射中打印元素的值。但是，由于我们使用的是bpf_map_lookup_and_delete_element，因此第一次迭代也会删除
映射中的元素。循环第二次尝试获取元素时，此代码将失败，并将使用“not found”错误ENOENT填充errno变量。

到目前为止，我们并没有花太多时间去研究并发访问BPF映射中的同一信息时会发生什么。接下来让我们讨论一下。

#### 并发访问映射元素

使用BPF映射的挑战之一是许多程序可以同时访问相同的映射。这可以可能给我们的BPF程序引入竞态，并访问映射中元素的时候可能出现不可预料的情况。为了防止出现竞态，BPF引入了BPF自旋锁的概念，该概念使您可以在操作映射元素时锁定对映射元素的访问。自旋锁只对数组，散列，和cgroup中存储映射有效。

有两个BPF辅助函数可与自旋锁一起使用：bpf_spin_lock 锁定元素，而bpf_spin_unlock 解锁该元素。这些帮助程序访问包含信号量的元素时，会与信号量协调工作。信号量被锁定后，其他程序将无法访问元素的值，它们会等到信号量被解锁为止。同时，BPF自旋锁引入了一个新的标志，用户态程序可以使用该标志来更改该锁的状态。该标志称为BPF_F_LOCK。

要使用自旋锁，我们需要做的第一件事是创建要锁定访问的元素，然后添加信号量：

```c
    struct concurrent_element { 
        struct bpf_spin_lock semaphore; 
        int count;
    }
```

我们将此结构存储在BPF映射中，并在元素中使用信号量来防止对其进行不必要的访问。现在，我们可以声明将包含这些元素的映射。该映射必须使用BPF类型格式（BTF）进行注释，以便验证者知道如何解释该结构。通过将调试信息添加到二进制对象，类型格式使内核和其他工具对BPF数据结构有了更丰富的了解。因为此代码将在内核中运行，所以我们可以使用libbpf提供的内核宏来注​​释此并发映射：

```c
    struct bpf_map_def SEC("maps") concurrent_map = { 
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(int),
        .value_size = sizeof(struct concurrent_element), 
        .max_entries = 100,
    };

    BPF_ANNOTATE_KV_PAIR(concurrent_map, int, struct concurrent_element);
```

在BPF程序中，我们可以使用两个锁定帮助程序来防止这些元素出现竞态。即使信号量已锁定，我们的程序仍可以保证能够安全地修改元素的值：

```c
    int bpf_program(struct pt_regs *ctx) { 
        intkey=0;
        struct concurrent_element init_value = {}; 
        struct concurrent_element *read_value;

        bpf_map_create_elem(&concurrent_map, &key, &init_value, BPF_NOEXIST);

        read_value = bpf_map_lookup_elem(&concurrent_map, &key);
        bpf_spin_lock(&read_value->semaphore);
        read_value->count += 100;
        bpf_spin_unlock(&read_value->semaphore);
    }
```

本示例使用一个新对象初始化并发映射，该对象可以锁定对其值的访问。然后，它从映射中获取该值并锁定其信号量，以便它可以保存计数值，从而防止数据争用。使用该值完成操作后，它将释放锁定，以便其他映射可以安全地访问该元素。

从用户态，我们可以使用标志 BPF_F_LOCK 保留对并发映射中元素的引用。您可以将此标志与辅助函数 bpf_map_update_elem和 bpf_map_lookup_elem_flags 一起使用。该标志使您无需担心数据争用就可以在适当位置更新元素。

*在更新哈希映射以及更新数组和cgroup存储映射时，BPF_F_LOCK 的行为略有不同。对于后两者，更新就位，并且要执行更新的元素必须在映射中存在。对于哈希映射，如果该元素尚不存在，则程序会将该元素的存储桶锁定在该映射中，并插入一个新元素。*

自旋锁并非总是必需的。如果仅在映射中汇总值，则不需要它们。但是，如果您要确保并发程序在对映射执行某些操作时不会改变映射中的元素，以保持原子性，则它们很有用。

在本节中，您已经了解了可以对BPF映射执行的操作；但是，到目前为止，我们仅处理一种类型的映射。 BPF包含更多映射类型，您可以在不同情况下使用。我们将解释BPF定义的所有类型的映射，并向您展示如何在不同情况下使用它们的特定示例。

### BPF 映射类型

Linux文档将映射定义为通用数据结构，您可以在其中存储不同类型的数据。多年来，内核开发人员添加了许多专用数据结构，这些结构在特定用例中更加高效。本节探讨每种类型的映射以及如何使用它们。

#### 哈希表映射

哈希表映射是添加到BPF中的第一个通用映射。它们以 BPF_MAP_TYPE_HASH 类型定义。它们的实现和用法类似于您可能熟悉的其他哈希表。您可以使用任意大小的键和值。内核会根据需要为您分配和释放它们。在哈希表映射上使用 bpf_map_update_elem 时，内核会原子替换元素。

哈希表映射经过优化，可以非常快速地进行查找；它们对于保持经常读取的结构化数据很有用。让我们看一个示例程序，该程序使用它们来跟踪网络IP及其速率限制：

```c
    #define IPV4_FAMILY 1
    struct ip_key { 
        union {
            __u32 v4_addr;
            __u8 v6_addr[16];
        };
        __u8 family;
        };

    struct bpf_map_def SEC("maps") counters = { 
        .type = BPF_MAP_TYPE_HASH, 
        .key_size = sizeof(struct ip_key), 
        .value_size = sizeof(uint64_t), 
        .max_entries = 100,
        .map_flags =BPF_F_NO_PREALLOC 
    };
```

在此代码中，我们声明了结构化键，并且将使用它来保留有关IP地址的信息。我们定义了我们的程序将用来追踪速率限制的映射。您可以看到我们在此映射中将IP地址用作键。这些值将是我们的BPF程序从特定IP地址接收网络数据包的次数。

让我们写一个小的代码片段来更新内核中的那些计数器：

```c
    uint64_t update_counter(uint32_t ipv4) { 
        uint64_t value;
        struct ip_key key = {};
        key.v4_addr = ip4;
    
        key.family = IPV4_FAMILY;

        bpf_map_lookup_elem(counters, &key, &value);
        (*value) += 1;
    }
```

此函数采用从网络数据包中提取的IP地址，并使用我们声明的复合键执行映射查找。在这种情况下，我们假设我们先前已将计数器初始化为零值；否则，bpf_map_lookup_elem 调用将返回负数。

#### 数组映射

数组映射是添加到内核的第二种BPF映射。它们以 BPF_MAP_TYPE_ARRAY 类型定义。初始化数组映射时，其所有元素都已预先分配在内存中，并设置为零值。因为这些映射由一片元素支持，所以键是数组中的索引，并且它们的大小必须恰好是四个字节。

使用数组映射的一个缺点是，无法删除映射中的元素，并且不能使数组变小。如果您尝试在数组映射上使用 map_delete_elem，则调用将失败，结果将显示错误EINVAL。

数组映射通常用于存储可以更改值的信息，但通常行为固定。人们使用它们来存储具有预定义分配规则的全局变量。由于无法删除元素，因此可以假定特定位置的元素始终表示相同的元素。

需要记住的另一点是 map_update_elem 不是原子的，就像您在哈希表映射中看到的那样。如果正在进行更新，则同一程序可以从同一位置同时读取不同的值。如果您将计数器存储在数组映射中，则可以使用内核的内置函数 __sync_fetch_and_add 对映射值执行原子操作。

#### 程序数组映射

程序数组映射是添加到内核的第一个专用映射。它们以 BPF_MAP_TYPE_PROG_ARRAY 类型定义。您可以使用这种类型的映射来使用它们的文件描述符标识符来存储对BPF程序的引用。结合帮助程序 bpf_tail_call，此映射使您可以在程序之间跳转，从而绕过单个BPF程序的最大指令限制并降低了实现复杂性。

使用此专用映射时，需要考虑一些事项。要记住的第一个方面是键和值的大小都必须为四个字节。要记住的第二个方面是，当您跳到新程序时，新程序将重用相同的内存堆栈，因此您的程序不会消耗所有可用的内存。最后，如果您尝试跳到映射中不存在的程序，则尾调用将失败，并且当前程序将继续执行。

让我们深入详细的示例，以了解如何更好地使用这种类型的映射：

```c
    struct bpf_map_def SEC("maps") programs = { 
        .type = BPF_MAP_TYPE_PROG_ARRAY, 
        .key_size = 4,
        .value_size = 4,
        .max_entries = 1024,
    };
```

首先，我们需要声明我们的新程序映射（如前所述，键和值的大小始终为四个字节）：

```c
    intkey=1;
    struct bpf_insn prog[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0), // assign r0 = 0
        BPF_EXIT_INSN(), // return r0 
    };
    prog_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, prog, sizeof(prog), "GPL"); 
    bpf_map_update_elem(&programs, &key, &prog_fd, BPF_ANY);
```

我们需要声明要跳转到的程序。在这种情况下，我们正在编写一个BPF程序，其唯一目的是返回0。我们使用 bpf_prog_load 将其加载到内核中，然后将其文件描述符标识符添加到程序映射中。

现在我们已经存储了该程序，我们可以编写另一个跳转到它的BPF程序。 BPF程序只有具有相同的类型，才能跳转到其他程序。在这种情况下，我们会将程序附加到kprobe追踪中，就像在第2章中看到的那样：

```c
    SEC("kprobe/seccomp_phase1")
    int bpf_kprobe_program(struct pt_regs *ctx) {
        intkey=1;
        /* dispatch into next BPF program */ 
        bpf_tail_call(ctx, &programs, &key);

        /* fall through when the program descriptor is not in the map */
        char fmt[] = "missing program in prog_array map\n"; 
        bpf_trace_printk(fmt, sizeof(fmt));
        return 0;
    }
```

使用 bpf_tail_call 和 BPF_MAP_TYPE_PROG_ARRAY，您最多可以链接32个嵌套的调用。这是防止无限循环和内存耗尽的明确限制。

#### Perf Events 数组映射

这些类型的映射将 perf_events 数据存储在缓冲区环中，该环在BPF程序和用户态程序之间实时通信。它们以BPF_MAP_TYPE_PERF_EVENT_ARRAY 类型定义。它们旨在将内核追踪工具发出的事件转发给用户态程序，以进行进一步处理。这是最有趣的映射类型之一，也是许多可观察性工具的基础，我们将在下一章中讨论这些工具。用户态程序充当等待内核事件的侦听器，因此您需要确保在初始化内核中的BPF程序之前，代码就开始侦听。

让我们看一个例子，说明如何追踪计算机执行的所有程序。在跳入BPF程序代码之前，我们需要声明将要从内核发送到用户态的事件结构：

```c
    struct data_t { 
        u32 pid;
        char program_name[16]; 
    };
```

现在，我们需要创建将事件发送到用户态的映射：

```c
    struct bpf_map_def SEC("maps") events = { 
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, 
        .key_size = sizeof(int),
        .value_size = sizeof(u32), 
        .max_entries = 2,
    };
```

在声明了数据类型和映射之后，我们可以创建BPF程序来捕获数据并将其发送到用户态：

```c
    SEC("kprobe/sys_exec")
    int bpf_capture_exec(struct pt_regs *ctx) {
        data_t data;
        // bpf_get_current_pid_tgid returns the current process identifier data.pid = bpf_get_current_pid_tgid() >> 32;
        // bpf_get_current_comm loads the current executable name bpf_get_current_comm(&data.program_name, sizeof(data.program_name)); 
        bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));
        return 0;
    }

```

在此代码段中，我们使用 bpf_perf_event_output 将数据附加到映射上。由于这是实时缓冲区，因此您无需担心映射中元素的键；内核负责将新元素添加到映射中，并在用户态程序对其进行处理后刷新它。

在第4章中，我们将讨论这些类型的映射的更高级用法，并提供用户态中处理程序的示例。

#### Per-CPU 哈希映射

此类映射是 BPF_MAP_TYPE_HASH 的精简版本。这些映射以 BPF_MAP_TYPE_PERCPU_HASH 类型定义。当您分配这些映射之一时，每个CPU都会看到其自己的映射隔离版本，这使其在高性能的查找和聚合中效率更高。如果您的BPF程序收集指标并将其汇总到哈希表映射中，则这种类型的映射很有用。

#### Per-CPU 数组映射

这种类型的映射也是 BPF_MAP_TYPE_ARRAY 的完善版本。它们以 BPF_MAP_TYPE_PERCPU_ARRAY 类型定义。就像以前的映射一样，当您分配这些映射中的一个时，每个CPU都会看到其自己的隔离版本的映射，这使得它对于高性能的查找和聚合更加高效。

#### 栈追踪映射

这种类型的映射存储正在运行的进程中的堆栈跟踪。它们以 BPF_MAP_TYPE_STACK_TRACE 类型定义。连同该映射一起，内核开发人员已经添加了帮助程序 bpf_get_stackid 来帮助您使用堆栈跟踪填充该映射。该帮助程序把该映射当作参数并根据一系列标志，以便您可以指定是否只希望从内核，用户态或两者都进行追踪。帮助程序返回与添加到映射的元素关联的键。

#### Cgroup 数组映射

这种类型的映射存储对cgroup的引用。 Cgroup数组映射以 BPF_MAP_TYPE_CGROUP_ARRAY 类型定义。从本质上讲，它们的行为类似于 BPF_MAP_TYPE_PROG_ARRAY，但是它们存储指向cgroup的文件描述符标识符。
当您要在BPF映射之间共享cgroup引用以控制流量，调试和测试时，此映射很有用。让我们来看一个如何填充此映射的示例。我们从映射定义开始：

```c
    struct bpf_map_def SEC("maps") cgroups_map = { 
        .type = BPF_MAP_TYPE_CGROUP_ARRAY, 
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t), 
        .max_entries = 1,
    };
```

我们可以通过打开包含cgroup信息的文件来检索cgroup的文件描述符。我们将打开控制Docker容器CPU占用比例的cgroup，并将该cgroup存储在我们的映射中：


```c
    int cgroup_fd, key = 0;
    cgroup_fd = open("/sys/fs/cgroup/cpu/docker/cpu.shares", O_RDONLY);

    bpf_update_elem(&cgroups_map, &key, &cgroup_fd, 0);
```

#### LRU哈希和 Per-CPU 哈希映射

这两种类型的映射是哈希表映射，就像您先前看到的那样，但是它们还实现了内部LRU缓存。 LRU代表最近最少使用，这意味着如果映射已满，则这些映射将删除不经常使用的元素，以便为映射中的新元素腾出空间。因此，只要您不介意丢失最近没有使用过的元素，就可以使用这些映射插入超出最大限制的元素。它们用 BPF_MAP_TYPE_LRU_HASH 和 BPF_MAP_TYPE_LRU_PERCPU_HASH 类型定义。

该映射的每个cpu版本与您之前看到的其他每个cpu映射略有不同。该映射仅保留一个哈希表来存储映射中的所有元素，并且每个CPU使用不同的LRU缓存，这样可以确保每个CPU中使用最多的元素保留在映射中。

#### LPM Trie 映射

LPM Trie 映射是使用最长前缀匹配（LPM）来查找映射中元素的映射类型。 LPM是一种从树中任何其他匹配项中选择与最长查找关键字匹配的树中元素的算法。该算法用于路由器和其他保持流量转发表以将IP地址与特定路由匹配的设备中。这些映射以BPF_MAP_TYPE_LPM_TRIE 类型定义。

这些映射要求其键大小为8的倍数，范围为8到2,048。如果您不想实现自己的键，则内核会提供一种可用于这些键的结构，称为bpf_lpm_trie_key。

在下一个示例中，我们将两条转发路由添加到映射，然后尝试将IP地址与正确的路由进行匹配。首先，我们需要创建映射：

```c
    struct bpf_map_def SEC("maps") routing_map = { 
        .type = BPF_MAP_TYPE_LPM_TRIE,
        .key_size = 8,
        .value_size = sizeof(uint64_t), 
        .max_entries = 10000,
        .map_flags = BPF_F_NO_PREALLOC,
    };
```

我们将使用以下三个转发路由填充此映射：192.168.0.0/16、192.168.0.0/24和192.168.1.0/24：

```c
    uint64_t value_1 = 1;
    struct bpf_lpm_trie_key route_1 = {.data = {192, 168, 0, 0}, .prefixlen = 16}; 
    uint64_t value_2 = 2;

    struct bpf_lpm_trie_key route_2 = {.data = {192, 168, 0, 0}, 
    .prefixlen = 24}; 
    uint64_t value_3 = 3;
    struct bpf_lpm_trie_key route_3 = {.data = {192, 168, 1, 0}, .prefixlen = 24};

    bpf_map_update_elem(&routing_map, &route_1, &value_1, BPF_ANY);
    bpf_map_update_elem(&routing_map, &route_2, &value_2, BPF_ANY);
    bpf_map_update_elem(&routing_map, &route_3, &value_3, BPF_ANY);

```

现在，我们使用相同的键结构来查找正确的匹配的IP 192.168.1.1/32：

```c
    uint64_t result;
    struct bpf_lpm_trie_key lookup = {.data = {192, 168, 1, 1}, .prefixlen = 32};

    int ret = bpf_map_lookup_elem(&routing_map, &lookup, &result); 
    if (ret == 0)
        printf("Value read from the map: '%d'\n", result);
```

在此示例中，192.168.0.0 / 24和192.168.1.0/24都可以与查找IP匹配，因为它在两个范围内。但是，由于此映射使用LPM算法，因此将使用键192.168.1.0/24的值填充结果。

#### 映射数组和映射哈希

BPF_MAP_TYPE_ARRAY_OF_MAPS 和 BPF_MAP_TYPE_HASH_OF_MAPS 是两种类型的映射，用于存储对其他映射的引用。它们仅支持一种间接级别，因此您不能使用它们来存储映射的映射，等等。这样可以确保您不会因意外存储无限链接的映射而浪费所有内存。

当您希望能够在运行时替换整个映射时，这些类型的映射非常有用。如果所有映射都是全局映射的子级，则可以创建全状态快照。内核确保父映射中的任何更新操作都等待，直到删除对旧子映射的所有引用，然后再完成操作。

#### 设备映射

这种特殊类型的映射存储对网络设备的引用。这些映射以 BPF_MAP_TYPE_DEVMAP 类型定义。它们对于希望在内核级别操纵流量的网络应用程序很有用。您可以构建指向特定网络设备的端口虚拟映射，然后使用帮助程序 bpf_redirect_map 重定向数据包。

#### CPU映射

BPF_MAP_TYPE_CPUMAP是另一种映射类型，允许您转发网络流量。在这种情况下，映射将对主机中不同CPU的引用存储。就像以前的映射类型一样，您可以将此映射与bpf_redirect_map帮助器一起使用，以
重定向数据包。但是，此映射将数据包发送到其他CPU。这允许您将特定的CPU分配给网络堆栈，以实现可伸缩性和隔离性。

#### 打开套接字映射

BPF_MAP_TYPE_XSKMAP 是一种映射类型，用于存储对打开套接字的引用。像以前的映射一样，在这种情况下，这些映射对于在套接字之间转发数据包很有用。

#### 套接字数组和哈希映射

BPF_MAP_TYPE_SOCKMAP和BPF_MAP_TYPE_SOCKHASH是两个专用映射，用于存储对内核中打开套接字的引用。像以前的映射一样，这种类型的映射与帮助程序bpf_redirect_map结合使用，将套接字缓冲区从当前XDP程序转发到另一个套接字。

它们的主要区别在于，其中一个使用数组存储套接字，而另一个使用哈希表。使用哈希表的优点是，您可以直接通过其键访问套接字，而无需遍历整个映射来查找它。内核中的每个套接字都由一个五元组键标识。这五个元组包括建立双向网络连接的必要信息。使用此映射的哈希表版本时，可以将此键用作映射中的查找键。

#### Cgroup存储 和 Per-CPU存储映射

引入了这两种类型的映射，以帮助开发人员使用附加到cgroup的BPF程序。正如您在有关BPF程序类型的第2章中所看到的那样，通过使用 BPF_PROG_TYPE_CGROUP_SKB，可以将BPF程序与控制组连接和分离，并将它们的运行时隔离到特定的cgroup。这两个映射的定义类型为 BPF_MAP_TYPE_CGROUP_STORAGE 和 BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE。

从开发人员的角度来看，这些类型的映射类似于哈希表映射。内核提供了一个帮助程序来为此映射生成键 bpf_cgroup_storage_key，其中包括有关cgroup节点标识符和附件类型的信息。您可以在此映射上添加所需的任何值；它的访问将仅限于附加cgroup中的BPF程序。

这些映射有两个限制。首先是您不能从用户空间在映射中创建新元素。内核中的BPF程序可以使用 bpf_map_update_elem 创建元素，但是，如果您从用户态使用此方法并且该键尚不存在，则 bpf_map_update_elem 将失败，并且errno将被设置为ENOENT。第二个限制是您不能从该映射中删除元素。 bpf_map_delete_elem 始终失败，并将errno设置为EINVAL。

就像您之前在其他类似的映射上看到的那样，这两种类型的映射之间的主要区别在于 BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE为每个CPU保留一个不同的哈希表。

#### 重用端口套接字映射

这种特殊类型的映射存储对套接字的引用，这些引用可以由系统中的开放端口重用。它们以 BPF_MAP_TYPE_REUSE PORT_SOCKARRAY类型定义。这些映射主要与 BPF_PROG_TYPE_SK_REUSEPORT 程序类型一起使用。它们结合在一起，使您可以控制如何过滤和处理来自网络设备的传入数据包。例如，即使两个套接字都连接到同一端口，您也可以决定将哪些数据包发送到哪个套接字。

#### 队列映射


