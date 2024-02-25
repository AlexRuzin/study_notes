# Study Notes
My personal study notes that I have been collecting over the years, but in markdown for convenience purposes

Version 0.1

* **
# Table of Contents
- [C++ Programming (the language of the old gods and universe)](#c---programming--the-language-of-the-old-gods-and-universe-)
  * [C++ Versions](#c---versions)
    + [C++98](#c--98)
    + [C++03](#c--03)
    + [C++11](#c--11)
    + [C++14](#c--14)
    + [C++17](#c--17)
      - [Structured Bindings](#structured-bindings)
      - [`constexpr`](#-constexpr-)
      - [Fold Expressions](#fold-expressions)
      - [Structured Initialization](#structured-initialization)
      - [Lambdas](#lambdas)
      - [UTF-8 Character literals](#utf-8-character-literals)
      - [Other features](#other-features)
    + [C++20](#c--20)
  * [Compilers](#compilers)
  * [Unit Testing](#unit-testing)
  * [Object Oriented Programming (OOP)](#object-oriented-programming--oop-)
  * [Standard Template Library (the [un]holy STL)](#standard-template-library--the--un-holy-stl-)
    + [Containers and Respective Polynomial Times/Complexity](#containers-and-respective-polynomial-times-complexity)
    + [Synchronization and Multi-threading](#synchronization-and-multi-threading)
      - [Headers](#headers)
      - [Mutexes](#mutexes)
      - [Locks](#locks)
      - [Condition Variables](#condition-variables)
        * [Atomics](#atomics)
        * [Memory Order Symantics](#memory-order-symantics)
        * [Common Memory Ordering Use Cases ***](#common-memory-ordering-use-cases----)
      - [Thread objects](#thread-objects)
    + [Smart Pointers](#smart-pointers)
    + [Templates and Metaprogramming](#templates-and-metaprogramming)
      - [`decltype`](#-decltype-)
    + [Algorithms](#algorithms)
      - [Sorting](#sorting)
      - [Searching](#searching)
      - [Other Operations](#other-operations)
    + [Iterators](#iterators)
    + [Function Objects](#function-objects)
  * [String Literals](#string-literals)
  * [RAII (Resource Allocation Is Initialization)](#raii--resource-allocation-is-initialization-)
  * [Other C++ notes](#other-c---notes)
  * [Locality](#locality)
- [Windows (win32) Interfaces and Internals](#windows--win32--interfaces-and-internals)
  * [Communications and IPC](#communications-and-ipc)
  * [Active Template Library (ATL)](#active-template-library--atl-)
  * [Win32 APIs](#win32-apis)
    + [Named Pipes](#named-pipes)
    + [Mailslots](#mailslots)
    + [Winsocks](#winsocks)
    + [RPC](#rpc)
    + [Memory-mapped files](#memory-mapped-files)
    + [MSMQ](#msmq)
    + [Process Injection](#process-injection)
    + [Registry functions](#registry-functions)
    + [Component Object Model (COM)](#component-object-model--com-)
- [Windows Driver Programming / NT Kernel](#windows-driver-programming---nt-kernel)
  * [IRP Callbacks and Initialization](#irp-callbacks-and-initialization)
    + [`IRP_MJ_DEVICE_CONTROL`](#-irp-mj-device-control-)
  * [Usermode Communications](#usermode-communications)
    + [IOCTL](#ioctl)
- [Python](#python)
  * [Language Symantics](#language-symantics)
  * [Data Structures and Complexity](#data-structures-and-complexity)
    + [list []](#list---)
    + [Tuple ()](#tuple---)
    + [Set {}](#set---)
    + [Dictionary / map](#dictionary---map)
    + [Bytes](#bytes)
    + [bytearray](#bytearray)
    + [deque](#deque)
  * [Decorators](#decorators)
  * [OOP / Python Classes](#oop---python-classes)
    + [Method overriding](#method-overriding)
    + [Method overloading (ie adding two classes together, using a defined operator)](#method-overloading--ie-adding-two-classes-together--using-a-defined-operator-)
  * [List Comprehension](#list-comprehension)
  * [Dictionary comprehension](#dictionary-comprehension)
  * [Generators](#generators)
  * [`with` statement](#-with--statement)
  * [Lambda functions (anonymous functions)](#lambda-functions--anonymous-functions-)
  * [Slicing (like in golang)](#slicing--like-in-golang-)
  * [Unpacking](#unpacking)
  * [`global` and `nonlocal` keywords](#-global--and--nonlocal--keywords)
  * [`yield` keyword](#-yield--keyword)
  * [Ellipsis (`...`)](#ellipsis-----)
  * [Walrus Operator (`:=`)](#walrus-operator-------)
  * [`f` strings, Format strings](#-f--strings--format-strings)
  * [Type hints (Type Annotations)](#type-hints--type-annotations-)
  * [Data Classes (library)](#data-classes--library-)
  * [Other language notes](#other-language-notes)
- [golang Programming Language](#golang-programming-language)
  * [Variables](#variables)
  * [Functions](#functions)
  * [Structs and methods](#structs-and-methods)
  * [Control](#control)
  * [Slices and Arrays](#slices-and-arrays)
  * [Maps](#maps)
  * [Pointers](#pointers)
  * [Goroutines and channels](#goroutines-and-channels)
  * [Interfaces](#interfaces)
  * [Golange packages](#golange-packages)
- [Windows API](#windows-api)
- [Network Engineering and Security](#network-engineering-and-security)
  * [PKI (Public Key Infrastructure)](#pki--public-key-infrastructure-)
    + [Public and Private keys](#public-and-private-keys)
    + [Cryptographic primitives](#cryptographic-primitives)
      - [Symmetric and Asymmetric Ciphers](#symmetric-and-asymmetric-ciphers)
      - [Hash Algorithms](#hash-algorithms)
      - [Key Exchange Algorithms](#key-exchange-algorithms)
      - [Cryptographic Protocols and Suites](#cryptographic-protocols-and-suites)
      - [Message Authentication](#message-authentication)
      - [Stream and Block Ciphers](#stream-and-block-ciphers)
  * [TLS/SSL](#tls-ssl)
- [Malware Analysis and Research](#malware-analysis-and-research)
  * [Target APIs](#target-apis)
    + [Network functions](#network-functions)
    + [File Operations](#file-operations)
    + [Registry](#registry)
    + [Cryptographic functions (ransomware)](#cryptographic-functions--ransomware-)
    + [Dynamic loading](#dynamic-loading)
    + [WMI](#wmi)
    + [Code Injection](#code-injection)
    + [Anti-debugging](#anti-debugging)
  * [Code Injection Techniques](#code-injection-techniques)
    + [DLL Injection](#dll-injection)
    + [Process Hollowing](#process-hollowing)
    + [Remote Thread Injection](#remote-thread-injection)
    + [APC (Asynchronous Procedure Calls) Injection](#apc--asynchronous-procedure-calls--injection)
    + [Sample Hook Injection (C++/Win32)](#sample-hook-injection--c---win32-)
    + [Atom Bombing](#atom-bombing)
    + [Reflective DLL Injection](#reflective-dll-injection)
    + [VEH (Vectored Exception Handling) Hooking](#veh--vectored-exception-handling--hooking)
    + [Thread Execution Hijacking (context hijacking)](#thread-execution-hijacking--context-hijacking-)
  * [Anti-debugging](#anti-debugging-1)
    + [Exception Handling Anti-debugging](#exception-handling-anti-debugging)
    + [Delta computation (Timing Checks)](#delta-computation--timing-checks-)
    + [Check hardware breakpoints](#check-hardware-breakpoints)
    + [Process and Thread Blocks](#process-and-thread-blocks)
    + [PEB (Process Environment Block)](#peb--process-environment-block-)
    + [Parent Process Check](#parent-process-check)
    + [Virtual Machine Detection](#virtual-machine-detection)
  * [Tools](#tools)
    + [Wireshark / TCPDump](#wireshark---tcpdump)
  * [Snort IDS](#snort-ids)
    + [Suricata IDS](#suricata-ids)
    + [Bro/Zeek](#bro-zeek)
    + [Palo Alto NGFW](#palo-alto-ngfw)
    + [YARA](#yara)
    + [Python libraries for automation](#python-libraries-for-automation)
    + [Cuckoo Sandbox](#cuckoo-sandbox)
    + [Debuggers and Analysis Tools](#debuggers-and-analysis-tools)
  * [Attack Vectors (malware)](#attack-vectors--malware-)
  * [Major exploits / vulnerabilities](#major-exploits---vulnerabilities)
  * [Fileless malware](#fileless-malware)
  * [Malicious Techniques](#malicious-techniques)
  * [Detection Techniques](#detection-techniques)
  * [IOCs (Indicators of Compromise)](#iocs--indicators-of-compromise-)
- [File Formats](#file-formats)
  * [PE (Portable Executable)](#pe--portable-executable-)
  * [ELF (Extensible Linkable Format)](#elf--extensible-linkable-format-)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

* **

# C++ Programming (the language of the old gods and universe)
__TODO__ Major rewrite of this section


Multi-paradigm language (OOP)
Procedural (C, callback)
Imperative (uses statements to change the state of the program)
Functional
Generic, modular

* **
## C++ Versions
_TODO_
### C++98
### C++03
### C++11
### C++14
### C++17
#### Structured Bindings
`auto [x, y] = std::make_pair(10, 20);`
`std::make_pair()` Create a `std::pair` object

#### `constexpr`

Allows the compiler to conditionally compile a type based on template parameters
```
template <typename T>
void foo(T value) {
    if constexpr (std::is_integral_v<T>) {
        // Compiled if code is an integral type
    }
}
```

#### Fold Expressions
Variadic template code
```
template <typename... Args>
auto sum(Args... args) {
    return (args + ...);
}
```

#### Structured Initialization
```
struct Point {
    int x;
    int y;
};

Point p{10, 20};
```

#### Lambdas
`constexpr auto add = [](int x, int y) { return x + y; };`

#### UTF-8 Character literals
_more on string literals below_
`u8'€'; // utf8_char type`

#### Other features
`std::variant`
`std::for_each` iterator
`<filesystem>` header
`std::make_unique<T>` initializes a `unique_ptr` of type `T`

### C++20

Personal study notes.
test

## Compilers
LLVM
VC++
gcc
CLang
Intel C++

## Unit Testing
_TODO_

*gtest* package from Google

## Object Oriented Programming (OOP)
Really over-simplified version of OOP
* Encapsulation
    *Classes* 
    Wrapping data and information in a single unit, _I.E. encapsulating complexity away from the whole, by limiting it to a single object_
* Inheritance
    The concept of a class inheriting the properties, state, or variables of another class
    *Derived Class*: the class that inherits from another class (i.e. child)
    *Base Class*: the class being inherited from
* Polymorphism
    Achieved through function overriding (separate from *overloading*, which allows one function to have multiple signatures and definitions)
    In greek: _Taking many forms_ 
    ```
    class A {
        public:
        int func(void) {
            return 1;
        }
    };

    class B : public A {
        public:
        int func(void) { // func is overridden by class B implementation
            return 2; 
        }
    }
    ```
* Abstraction
    Virtual functions and interface classes (i.e. pure virtual classes)
    
    Useful for abstracting away the complexity of a certain class, for example:
        `class Logger` is an interface class, it can log to either OutputDebugString(), stdout, or to a file. It has purely virtual methods:
        `virtual int func(std::string s) = 0;`
        `class ConsoleLogger : Public Logger` implements `func`, such that the definition of `func` outputs to stdout

## Standard Template Library (the [un]holy STL)
### Containers and Respective Polynomial Times/Complexity
* `std::vector<>` (dynamic expand array, similar to a C array but you can iterate and push to it)
    access: O(1)
    insert/remove at end O(1)
    insert remove at middle O(n)
* `std::list` (essentially a linked list)
    access: O(n) at worst, search is not ideal
    insert/remove (beginning or end): O(1), relatively fast, otherwise O(n) at worst
* `std::deque` (double ended fast insert queue)
    access: O(1)
    insert at beginning or end: O(1), middle is O(n)
* `std::queue` (pretty much a queue)
    push: O(1)
    pop: O(1)
* `std::map` (dictionary)
    access, insert, removal: O(log(n)) <- hella fast
* `std::set` (unique keys in sorted order)
    _TODO_
    access, insert, remove: O(1) best, O(n) worst
* `std::unordered_set` (same as above, but not ordered based on element insertion/deletion)
* `std::pair` Pair, can be any type, simple container
* `std::tuple` Tuple can hold a collection of elements, each can be a different type

### Synchronization and Multi-threading
*See `signal.h` for a good example of this
Do not forget `std::unique_lock`, at end of scope, release an `std::mutex`
`std::unique_lock<std::mutex> mlock(syncMutex);`
#### Headers
```
<thread>
<mutex>
<future>
<atomic>
<condition_variable>
```

```
bool isRunning = false;

void func1(int param)
{
    while (isRunning) {
        Sleep(1000);
    }
}

int main(void)
{
    std::thread new_thread(func1, 0);

    new_thread->detach();

    Sleep(1000);

    isRunning = false;
    if (std::thread->is_joinable()) {
        std::thread->join();
    }

    return 0;
}
```

#### Mutexes
`std::mutex` `std::recursive_mutex` `std::timed_mutex` `std::recursive_timed_mutex`

#### Locks
Locks are used in RAII, used for synchronizing access to resources 
* `std::lock_guard` Locked on construction, unlocked on destruction, out of scope
* `std::unique_lock` Used in conjunction with `condition_variable`, can be locked an unlocked
* `std::scoped_lock` (C++17)

#### Condition Variables
* Used om conjunction with `std::unique_lock` 
* Condition variables that allow for safe management of `std::thread`
* Essentially wait for certain conditions to become true
* Used in conjunction with mutexes to synchronize threads, for example, **the condition variable waits until a mutex is released**

`std::condition_variable` in `<condition_variable>`

**Example in which you can send multiple signals to waiting threads, each will wait with a `condition_variable` until `mtx` is signalled**
```
std::mutex mtx;
std::condition_variable cv;
bool ready = false;

void worker(void) {

    // Acquire the mutex. i.e. reach the `CRITICAL_SECTION` for `lock`
    std::unique_lock<std::mutex> lock(mtx);

    // Wait until the lock is signalled, then execute lambda predicate
    cv.wait(lock, []{ return ready; });
}

void signal(void) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        ready = true;
    }

    cv.notify_one();
}
```

##### Atomics
`std::atomic` used for atomic (interlocked) operations in C++

##### Memory Order Symantics
* relaxed (`memory_order_relaxed`): There are no ordering or synchronization constraints, except the modification is interlocked
* consume (`memory_order_consume`): Rarely used _TODO_
* acquire (`memory_order_acquire`): Ensures that memory writes before the atomic operation are not moved after it.
* release (`memory_ordr_release`): Ensures that memory writes after the atomic operation are not moved before it.
* acquire-release (`memory_order_acq_rel`): Combines both acquire and release semantics.
* sequentially consistent (`memory_order_seq_cst`): The strongest memory ordering, ensuring a total order of all sequentially consistent operations.

```
std::atomic<int> counter(0);

void increment() {
    for (int i = 0; i < 10000; ++i) {
        counter++;
    }
}

int main() {
    std::vector<std::thread> threads;

    // Create 10 threads to increment the counter
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back(increment);
    }

    // Wait for all threads to finish
    for (auto &thread : threads) {
        thread.join();
    }

    std::cout << "Counter value: " << counter << std::endl;

    return 0;
}
```

##### Common Memory Ordering Use Cases ***
1. `std::memory_order_seq_cst` (Sequentially constant)
* Default memory order for atomics, strictest and most intuitive memory order. 
* Prevents any reordering of read/write operations
* Is not ideal for performance
2. `std::memory_order_acquire` and `std::memory_order_release`
* Used for implementing mutexes, condition variables (), designing lock free data structures
3. `std::memory_order_relaxed` 
* No ordering requirements, very fast
* Statistics collection, flag settings, **counter increments**

```
std::atomic<bool> flag(false);

flag.store(true, std::memory_order_seq_cst);
flag.load(std::memory_order_seq_cst);
```

#### Thread objects
`std::thread tNewThread = std::thread(callback, 0);`

`std::thread` object containing an instance of a thread

`thread->join()`, `thread->detach()`, `thread->is_joinable()`

### Smart Pointers
Smart way to make unsafe pointer allocation/deallocation in C safer by performing automatic garbage collection

`std::unique_ptr<TypeObj> a = PtrTypeObjFactory();` Creates a `std::unique_ptr`, using a factory. 

`std::unique_ptr` own their pointer uniquely. When the `std::unique_ptr<>` instance goes out of scope, it will automatically destroy the object to which it points

`std::shared_ptr<>` holds a reference count. Once the reference count reaches 0, and all instances of the object are out of scope, delete the object pointed to by the shared_ptr

`std::auto_ptr<>` aye

### Templates and Metaprogramming
_TODO_

*SFINAE* (Substitution failure is not an error) 

Invalid substitution may not necessarily indicate an error

https://en.wikipedia.org/wiki/Substitution_failure_is_not_an_error#:~:text=Substitution%20failure%20is%20not%20an%20error%20(SFINAE)%20is%20a%20principle,to%20describe%20related%20programming%20techniques.

#### `decltype`
Retrieves the type of the variable, useful in templates:
```
int a = 5;
    decltype(a) b = a; // evaluates to int b = a;

decltype(auto) func(void) {
    int x = 5;
    return (x); //returns int& since x is an lvalue
}
```

### Algorithms
_TODO_
`<algorithm>` header

#### Sorting
`std::sort`
`std::stable_sort`
`std::partial_sort`

#### Searching
`std::find`, `std::binary_search`, `std::lower_bound`, `std::upper_bound`

#### Other Operations
`std::copy`, `std::move`, `std::replace`, `std::remove`, `std::merge`, `std::accumulate`

### Iterators
_TODO_
* Input Iterators, for reading; moving forward
* Output Iterators: For writing, moving forward
* Bidirectional Iterators: for rw, bi-directional
* Random Access Iterators
`std::begin()`, `std::end()`, `std::iterator`, `std::const_iterator`
`std::transform()`, `std::for_each()`

### Function Objects
_TODO_
<functional> header (functional programming)
*lambda expressions*

## String Literals
_TODO_ Improve on this.
```
	R"(\)" <- literal string, \ does not escape (const char *)
	L"asdfasdf" <- UTF-8 string (wchar_t)
	u"test" const char16_t* (UTF-16)
	U"test" const char32_t* (UTF-32)
```

## RAII (Resource Allocation Is Initialization)
A terrible name for a beautiful concept: encapsulating the lifecycle of a resource within a class constructor and destructor. Once the scope of the class has ended, the resource is automatically free'd. This can be implemented through the class constructor and destructor.

* Encapsulate a resource into a class, for example, a `HANDLE`'s lifecycle is managed by a `class`
* Access the resource via class, for example, interfacing with `HANDLE` is done via calling `class` methods
* The resource must be freed once at end of scope, _ie call on the destructor_

## Other C++ notes
* `vftable` or `vtable` is an array of function pointers that point to the definitions for that particular class
* **Livelock**: when two threads are running, polling, and waiting on each other for some event, thus a cyclic depedency and the threads become locked
* **Starvation**: indicates what the name suggests: a thread is perpetually denied access to a resource that are being locked by other competing threads. Occurs when lock aquisition is not fair, thus starvation

## Locality 
_not just C++, but a concept in architecture_
Refers to the access of the same value or related storage location
* **Temporal Locality**: Reuse of data in small time frames. For example in memory, if an address is accessed, there is a high chance it will be accessed again
* **Spatial Locality**: Refers to frequently used memory that are within close proximity, useful in caching

**Implementations and examples of Locality**
1. Caching: Both forms of locality are crucial for the effective design and utilization of cache memory in computing systems. Caches keep frequently accessed data and instructions close to the CPU to reduce the access time, and a good understanding of locality patterns can significantly enhance cache performance.

2. Algorithm Design: Algorithms can be optimized for better performance by arranging data structures and access patterns to maximize locality. For instance, iterating through an array sequentially exhibits high spatial locality, which is generally more cache-friendly than randomly accessing array elements.

3. Memory Hierarchy Design: Computer architectures are designed considering locality principles. This includes the implementation of various levels of caching (L1, L2, L3 caches), and the design of RAM and virtual memory.

4. Prefetching Strategies: Understanding data access patterns allows for effective prefetching, where the processor anticipates the needed data and loads it into the cache in advance.

**Summary**
    Deadlock: Threads are stuck waiting for each other, and there is no change in state without external intervention.
    Livelock: Threads are actively changing their state in response to each other, but no progress is made.
    Starvation: Some threads are unable to make progress because others are monopolizing the resources. The monopolizing threads are making progress.

* **
# Windows (win32) Interfaces and Internals
The glorious Win32 API and kernel!
## Communications and IPC
* **IOCTL** Communication between usermode and kernelmode. Remember that this is works by usermode calling on kernel mode using a particlar IOCTL code
* **Kernel Object Manipulation** Direct manipulation of kernel objects: i.e. threads, processes, etc
* **Remote Procedure Call (RPC)** Windows and UNIX protocol for defining callbacks in a master, called by slave applications
* **Mailslots** One-way IPC, applications register a mailslot and receive data from a single sender
* **Named Pipes** Named pipes are files/device objects that can be read and written to, and therefore allows for IPC and interfacing with drivers
* **Sockets** Useful for TCP/IP, can be used for IPC or "remote" IPC through the network, and using the network stack
* **Synchronization** Primitives are explained below
* **File System Communication** File I/O. Process can communicate through the fs
* **System Calls (syscalls)** Mechanism for calling the kernel via syscalls, mostly wrapped by `ntdll.dll` and `kernel32.dll`
* **Shared Memory** See below for APIs, but essentially `OpenProcess()`, `WriteProcessMemory()`, `MapViewOfSection()`, etc...
* **Message Queue (MSMQ)** MQ implementation from MS
* **Component Object Model (COM)** and **DCOM**, an extension of COM that allows for IPC and shared global objects, which can communicate over the network

## Move and Named Return Value Optimization (NRVO)
```
#include <iostream>

class Foo
{
public:
    int x = 0;

    // default ctor
    Foo()
    {
        std::cout << "Default ctor\n";
    }

    // copy ctor
    Foo(const Foo& rhs)
    {
        std::cout << "Copy ctor\n";
    }
};

Foo CreateFooA()
{
    return Foo();
}

Foo CreateFooB()
{
    Foo temp;
    temp.x = 42; // update member variable
    return temp;
}

int main()
{
    Foo t1(CreateFooA()); 
    Foo t2(CreateFooB()); // Object created twice
   
    return 0;
}
```

1. CreateFooA() creates a temporary Foo object to return.
2. The temporary object will then be copied into the object that will be returned by CreateFooA().
3. The value returned by CreateFooA() will then be copied into t1.

## Active Template Library (ATL)


## Win32 APIs
### Named Pipes
`CreateNamedPipe()`, `ConnectNamedPipe()`, `CreateFile()`, `ReadFile()`, `WriteFile()`
### Mailslots
`CreateMailslot()`, see above create/read/write file
### Winsocks
`WSASocket()`, `bind()`, `send()`, `recv()`, `listen()`, `accept()`
### RPC
_TODO_ Lookup MSRPC implementation
`RpcBindingFromStringBinding()`, `RpcBindingSetOption()`, `RpcStringBindingCompose()`
### Memory-mapped files
`CreateFileMapping()`, `MapViewOfFile()`
### MSMQ
`MQOpenQueue()`, `MQSendMessage()`, `MQRecvMessage()`
### Process Injection
`LoadLibrary()`, `CreateRemoteThread()`, stop thread, alter register state (`rip`) and resume thread
* Process Hollowing: Create suspended process, replace text segment resume thread
`WriteProcessMemory()`, `VirtualAllocEx()`
### Registry functions
_TODO_

### Component Object Model (COM)
* `IUnknown`: provides methods for reference counting an object, all objects must contain an IUnknown interface
* IDL (Interface Definition Language) used to define interfaces (in COM and DCOM/RPC)
`CoCreateInstance()`, `AddRef()` method, `Release()`, to increment or decrement reference count to an object

```
    CoCreateInstance()
    WMI L"ROOT\\CIMV2"
    FileSystem objects 
    ActiveX
    IE COM objects (Navigate())	
```

* **
# Windows Driver Programming / NT Kernel
* WDF (Windows Driver Framework)
* KMDF (Kernel-Mode Driver Framework)
* Minifilter: (filesystem and file i/o)

## IRP Callbacks and Initialization
```
DRIVER_OBJECT *drvObj = getDrvObj(); // Obtain driver object (i.e. instance of current driver)

// Set callbacks for DRIVER_DISPATCH
drvObj->MajorFunction[IRP_MJ_CREATE] = driverMyCreateHandler;
drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverDeviceControlHandler; 
```

### `IRP_MJ_DEVICE_CONTROL`
__Callback for usermode IOCTL__
```
drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverDeviceControlHandler; 

// IOCTL definitions
#define IOCTL_CTD_CMD_REQUEST \
   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// Sample callback from usermode
NTSTATUS driverDeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_CTD_CMD_REQUEST: // IO_BUFFERED request

    case IOCTL_CTD_CMD_RESPONSE:

    default:

    }
}
```

## Usermode Communications
### IOCTL
_https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes_
```
METHOD_BUFFERED
METHOD_IN_DIRECT
METHOD_OUT_DIRECT
METHOD_NEITHER
```
```
DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyIoctlHandler;
IoGetCurrentIrpStackLocation()
switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {}
#define IOCTL_MY_OPERATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
CreateFile(L"\\\\.\\YourDeviceName");
DeviceIoControl()
```

* **
# Python
## Language Symantics
* Dynamically typed
* Interpreted
* Scripted
* Garbage collector (internal reference counter)

## Data Structures and Complexity
* Mutability: i.e. does an object change (const)
* Ordering: does an object maintain order
* Duplicates: does an object maintain duplicate elements

### list []
Ordered, mutable, duplicates
```my_list = [ 1, 2, 3]
my_list.append(4)
print(my_list[3]) # output is 4 
```
* access: O(1)
* append: O(1)
* insert/delete: O(n)
* search: O(n) at worst
* len(): O(1)

### Tuple ()
Ordered, *immutable*, duplicates

when you need an ordered and immutable collection, which can also be used as a key in a dictionary. Tuples are suitable when you want to ensure the data remains unchanged and order matters.

`my_list = (1, 2, 3)`

* access: O(1)
* search: O(n)
* len(): O(1)

### Set {}
Unordered, mutable, no duplicates (advantage is that it removes duplicates automatically)
Fast search O(1) - O(n)

when you need a collection of unique elements and efficient membership testing, and when the order of elements and immutability are not important.

`my_list = {1, 2, 3}`

* insert: O(1) - O(n) worst
* delete: O(1) - O(n) worst
* search: O(1) - O(n) worst
* len(): O(1)
* frozenset is an immutable version of a _set_

### Dictionary / map 
Note: normal dictionary is initialized using below [] format, however, dict comprehension is initialized using {} for some reason

```my_dict = [ "a": 1, "b": 2 ]
my_dict["c"] = 3
```

* access: O(1)
* insert: O(1)
* delete: O(1)

### Bytes
Immutable array of bytes, i.e. string

`my_bytes = b'hello'`

### bytearray
*mutable* array of bytes

`my_array = bytearray(b'hello')`

`my_array[0] = ord('H') # switch element 0 to uppercase H`

### deque
double-ended queue

push / pop at O(1)

## Decorators
For extending the behaviour of functions. I.e. define a function used as a decorator, and "decorate" another function such that it is extended
Used in web frameworks for routing URLs to view functions, logging, authorization, etc

Useful in debugging and logging, timing, authentication (for a specific function):
```
def log_function_call(func):
    def wrapper(*args, **kwargs):
        print(f"Calling function: {func.__name__} with args {args} kwargs {kwargs})
        result = func(*args, *kwargs)
        print(f"{func.__name__} return {result})
        return result
    return wrapper

@log_function_call
def add(a, b)
    return a + b
add(3, 5)
```

## OOP / Python Classes
    Class: like C++ class, blueprint
    Object: instantiation
    Inheritance: Form child classes from parent classes
    Encapsulation: Hiding/abstracting members of a class/object
    Polymorphism: Overriding functions like in C++

```
class TestClass:
    species = "something"

    # initializer / constructor (C++)
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def get_description(self):
        print(f'Name: {self.name} Age: {self.age}')

    def print_param(self, param)
        print(f'Param: {param}')

def main()
    test = TestClass("asdf", 434)
    print(test.get_description())

def __name__ == "__main__":
    main()
```


### Method overriding 
```
class baseClass:
    def func(self):
        raise NotImplementedError("Subclass not implemented)

class childClass(baseClass):
    def func(self):
        print(f"implement {instance.__class__.__name__}")
```

### Method overloading (ie adding two classes together, using a defined operator)
Same as C++ overloading, but just have different parameter names, nbd
Decorators (@dec_function) can also be used to handle overloading

**Overloading operators**

```
class Point:
    def __init__(self, x = 0, y = 0):
        self.x = x
        self.y = y
    
    # overload the "+" operator
    def __add__(self, other): #other is the second class, for example c1 + c2, where both are classes
        return Point(self.x + other.x, self.y + other.y)

def main()
    p1 = Point(4, 3)
    p2 = Point(5, 6)
    p3 = p1 + p2 # implement operator override
```


## List Comprehension
_Method of merging lists (i.e.), specifically a sort of 'lambda' that can be embedded into a list initialization_
```
test = [ "a", "b", "c" ]
test2 = []

for x in test:
    if "a" in x:
        test2.append(x)

# Rather do something like this
test2 = [ x for x in test2 if "a" in x ]
```

## Dictionary comprehension
_Same as above, but allows you initialze a dictionary in an efficient way using a lambda_
`square_dict = { x: x**2 for x in range(10)}`



## Generators
**Generators are iterators, you can only iterate once**
**Generators do not store all the values in memory, they generate values**
Used in parsing large files, CSV, data streams, etc
Function that returns a *lazy iterator*

```
mygenerator = ( x * x for x in range(10))
for i in mygenerator:
    print(i)

# you cannot iterate the generator twice!!!
# i.e. this will not work:
for i in mygenerator:
    print(i0)
```

```
class first_n(object):
    def __init__(self, n):
        self.n = n
        self.num = 0

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if self.num < self.n:
            cur, self.num = self.num, self.num + 1
            return cur
        raise StopIteration()

sum_of_first_n = sum(first_n(100000))
```

## `with` statement
Automatic exception handling with certain functions and operations, produces cleaner code

```
with open('file_path', 'w') as file:
    file.write("test")
```

## Lambda functions (anonymous functions)

`multiply = lambda x, y: x * y`

## Slicing (like in golang)

```my_list = [ 1, 2, 3, 4, 5 ]
sublist = my_list[1:3] # copy from index 1 - 3, resultant is [2, 3]
```

## Unpacking
Allows the assignment from a sequence, list, set, tuple, into different variables
`a, b, *rest = range(10)`

## `global` and `nonlocal` keywords
Useful for modifying scope of variables

```
def outer():
    x = "local"
    def inner():
        nonlocal x
        x = "nonlocal" # x is now outside of current scope
    inner()
    return x
```

## `yield` keyword
**see [Generators](#generators)**
* Iterable is an object that counts a list, the list itself is an iterable or iterable
* A generator is an iterable, that is iterable only once
* `yield` is a keyword that is used like a `return`, except it returns a generator

```
mylist = range(10)

def create_generator():
    for i in mylist:
        yield i * i
    
mygenerator = create_generator()
print(mygenerator)
```

## Ellipsis (`...`)
_Indicates empty code section_
```
def func():
    ...
```

## Walrus Operator (`:=`)
_Assign values to variables in an expression_
`if (n := len(a)):`

## `f` strings, Format strings
`print(f"{variable}")`

## Type hints (Type Annotations) 
_Optional type hinting_
`def greet(name: str) -> str`

## Data Classes (library)
_Automatically generates `__init__` and `__repr__`_

```
from dataclasses import dataclass

@dataclass # decorator
class Point:
    x: int
    y: int
```

## Other language notes
* Global Interface Lock (GIL): Automatic object locking (mutex) for objects

* **
# golang Programming Language
* Multi-paradigm
* concurrent
* imperative
* functional 
* OOP
* static typing

## Variables
`var i = 10`
`i := 10`

## Functions
```
import (
    "errors"
    "fmt"
)

func div(x int, y int) (int, error) {
    if y == 0 {
        return 0, errors.New("Cannot divide by 0")
    }

    return x / y, nil
}

func main() {
    ret, err := div(5, 0)

    if err != nil {
        fmt.Println("Error:", err)
    }
}
```

## Structs and methods
```
type testStruct struct {
    name string
    a int
    b int
}

func (c testStruct) do_operation(x int, str string) (int, error) {
    //stuff
}

func main() {
    newStruct := testStruct(name: "test", a: 123);
    out, err := newStruct.do_operation(134134, "dfiaifj");
}
```

## Control
```
func main() {
    for i := 0; i < 1000; i++ {
        fmt.Println(i)
    }

    if num := 9; num == 9 {
        //smth
    }
}
```

## Slices and Arrays
**Array have fixed sizes, always const**
**Slices are dynamic**
```
// Slice can be initialzed with []
var a []int{1, 2, 3, 4, 5}
a.append(a, 6)

// Array must be constant, with a fixed size
var b [3]int{1, 2, 3}
var b [...]int(1, 2, 3) // array inferred by the compiler

// Get slice and form new slice
c := b[1:2] // get element 1 to element 2
```

## Maps
_see C++ or Python section for complexities, as they are similar_
```
m := make(map[string]int)
m["test"] = 1
```

## Pointers
_Similar to C, but safer_
```
i := 42
p := &42
fmt.Println(*p)
```

## Goroutines and channels
```
func f(in string) int
{
    fmt.Println(in)
}

func main()
{
    go f("test")

    // Create a nested thread and send data via channel (blocking)
    ch := make(chan string) // specify the type
    go func(param string) {
        sleep(1000)
        ch <- param // Send into channel
    }("test")

    //Spawn thread and block channel
    msg := <-ch
    fmt.Println(msg)
}
```

## Interfaces
_Similar to pure virtual classes, or interface classes in C++_
_Golangs polymorphism implementation_
```
type Speaker interface {
    Speak(param string) string // Define a virual/interface function
}

// Implementation for Dog
type Dog struct {}

func (f Dog) Speak(param string) {
    fmt.Println(param)
}

// Implementation for Car
type Cat struct {}

func (f Cat) Speak(param string) {
    fmt.Println(param)
}

func main() {
    dog := Dog{}
    dog.Speak("test")

    cat := Cat{}
    cat.Speak("test")
}
```

## Golange packages
	fmt  : formatted I/O
	net/http : http, obvz
	io/ioutil : file I/O and streaming
	os : OS interoperability
	encoding/json : JSON obvz
	html/template : HTML
	sync : synchronization / concurrency primitives
	time : time API
	
	gorilla/mux : URL router multiplexer
	golang.org/x/net/websocket : websocks implementation
	golang.org/x/oauth2: OAuth2 authorization via HTTP/REST (google)
	github.com/gorilla/sessions: cookie / fs

# Windows API

* **
# Network Engineering and Security
## PKI (Public Key Infrastructure)
### Public and Private keys
1. Key Generation
    * RSA
    * Choose two primes, \( p \), \( q \), and compute nonprime \( n \) such that \( n = p \times q \):
\( n = p \times q \) 
\( \phi(n) = (p-1) \times (q-1) \)
    * Choose an integer \( e \) s.t. \( 1 < e < \phi(n) \)  and \( e \) and \( \phi(n) \) are coprime (two numbers are *coprime* iff their GCD (greatest common divisor) is equal to 1)
    * Compute \( d \) as the modular multiplicative inverse of \( d \times e \mod \phi(n) \):
    \( d \times e \mod \phi(n) = 1 \)
    * Therefore:
    Public Key: \( (e, n) \)
    Private Key: \( (d, n) \)
2. Encryption:
        For message \( M \) and cyphertext \( C \): \( C = M^e \mod n \)
   Decryption:
        \( M = C^d \mod n \)
3. Digital Signatures
    * Signing a message involves generating a hash of the message, and encrypts it with its private key
    * To verify: the receiver decrypts the message using its public key and compares the hash to the message
4. Certificate Insurance
    * Certificate Authority (CA) verifys the identify of the recipient or sender. Root CAs are third party (i.e. DigiCert, Let's Encrypt, Komodo, GlobalSign)

### Cryptographic primitives
#### Symmetric and Asymmetric Ciphers
**Symmetric**
1. AES256
2. DES
3. 3DES
4. RC4, RC5, RC6
**Asymmetric**
1. RCA
2. ECC (Elliptic curve cryptography)

#### Hash Algorithms
1. MD5
2. CRC16, CRC32
3. DSA (Digital Signature Algorithm)
4. ECDSA (Elliptic Curve DSA)

#### Key Exchange Algorithms
1. Diffie-Hellman (DH) used to exchange keys over cleartext
2. ECDH (Elliptic Curve DH)

#### Cryptographic Protocols and Suites
1. SSL/TLS 1.3 
2. IPSec

#### Message Authentication
1. HMAC (Hash based authentication code) combination of a key and hash function

#### Stream and Block Ciphers
* **Stream Ciphers** encrypt one bit at a time (RC4)
* **Block Ciphers** Encrypt a chain of blocks (AES)

## TLS/SSL
<img src="images/SSL_Handshake_10-Steps-1.png">

* **
# Malware Analysis and Research 

## Target APIs
### Network functions
* `WSAStartup()`
* `socket()`
* `connect()`
* `send()`
* `recv()`
* `WSASend()`
* `WSARecv()`
* `bind()`
* `listen()`
* `accept()`
* `InternetOpen()`
* `InternetConnect()`
* `HttpSendRequest()`, `HttpOpenRequest()`

### File Operations
* `CreateFile()`
* `ReadFile()`, `WriteFile()`
* `DeleteFile()`
* `CopyFile()`, `MoveFile()`
* `SetFileAttributes()`

### Registry
* `RegOpenKeyEx()`
* `RegQueryValueEx()`
* `RegSetValueEx()`
* `RegCreateKeyEx()`
* `RegDeleteKey()`, `RegDeleteValue()`

### Cryptographic functions (ransomware)
_Include bcrypt.dll_
* `CryptAcquireContext()`
* `CryptEncrypt()`, `CryptDecrypt()`
* `CryptHashData()`
* `CryptDeriveKey()`
* `CryptExportKey()`, `CryptImportKey()`

### Dynamic loading
* Enumeration of IAT
* `LoadLibraryA/W()`
* `GetProcAddress()`

### WMI
* `IWbemServices::ExecQuery` : recon function, for direct querying of WQL

### Code Injection
* `VirtualAllocEx()`, `WriteProcessMemory()`, `CreateRemoteThread()`
* `SetWindowsHookEx()` : hooks processes
* `SetThreadContext()` function for modify context of remote TEB

### Anti-debugging
* `IsDebuggerPresent()`
* `CheckRemoteDebuggerPresent()`

## Code Injection Techniques
### DLL Injection
1. Open a `HANDLE` to the remote process
2. Allocate memory in the remote process, containing the target DLL name
3. Call `CreateRemoteThread()` with the parameter as in step 2

### Process Hollowing
1. Create process as `PROCESS_SUSPENDED`
2. Zero out legitimate code from the process
3. Set target shellcode or DLL to the remote process
4. Call `ResumeProcess()`

### Remote Thread Injection
1. `VirtualAllocEx()` with `PAGE_READWRITE_EXECUTABLE` flag
2. `WriteProcessMemory()` to target page
3. Call `CreateRemoteThread()` against target `HANDLE`

### APC (Asynchronous Procedure Calls) Injection
* An APC is queued to a thread of a process. When the thread enters an alertable state, the APC is executed

### Sample Hook Injection (C++/Win32)
__https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++__
```
#include "pch.h"
#include <iostream>
#include <Windows.h>

FARPROC messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};

int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	
	// print intercepted values from the MessageBoxA function
	std::cout << "Ohai from the hooked function\n";
	std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;
	
	// unpatch MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
	
	// call the original MessageBoxA
	return MessageBoxA(NULL, lpText, lpCaption, uType);
}

int main()
{
	// show messagebox before hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);

	HINSTANCE library = LoadLibraryA("user32.dll");
	SIZE_T bytesRead = 0;
	
	// get address of the MessageBox function in memory
	messageBoxAddress = GetProcAddress(library, "MessageBoxA");

	// save the first 6 bytes of the original MessageBoxA function - will need for unhooking
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, 6, &bytesRead);
	
	// create a patch "push <address of new MessageBoxA); ret"
	void *hookedMessageBoxAddress = &HookedMessageBox;
	char patch[6] = { 0 };
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);

	// patch the MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, patch, sizeof(patch), &bytesWritten);

	// show messagebox after hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);

	return 0;
}
```

### Atom Bombing
Using the global atom table to write code into memory of a target process, then trigger this code of execution
```
NTSTATUS
NtQueueApcThread(  
    IN HANDLE ThreadHandle,
    IN PPS_APC_ROUTINE ApcRoutine,
    IN PVOID SystemArgument1 OPTIONAL,
    IN PVOID SystemArgument2 OPTIONAL,
    IN PVOID SystemArgument3 OPTIONAL
    );
```

### Reflective DLL Injection
Manually loading a windows DLL, without using the standard API, this involves:
* Manually parsing PE and allocating memory for segments
* Write image segments to pages
* Resolve API, and write to IAT
* Resolve references

### VEH (Vectored Exception Handling) Hooking
* Using the VEH chain to manually route an exception handler to run code

### Thread Execution Hijacking (context hijacking)
* Alter context of remote thread (i.e. modify `rip` or `eip` registers to point to shellcode)

## Anti-debugging
* `IsDebuggerPresent()`
* `CheckRemoteDebuggerPresent()`
* `NtQueryInformationProcess()`

### Exception Handling Anti-debugging 
Using exception handlers to detect the presence of a debugger. Malware can generate exceptions to see how they are handled.

### Delta computation (Timing Checks)
Check delta between a and b, and if the delta is greater than the expected value, it may indicate a debugger stepping

### Check hardware breakpoints
`dr0-dr7` Registers contain values for debugging

### Process and Thread Blocks
* `NtQUeryObject()` detects debugging
* `CreateToolhelp32Snapshot()` enumerate processes and check for debugger running

### PEB (Process Environment Block)
`BeingDebugged` flag in PEB indicates an attached debugger
`NtGlobalFlag` may also be altered by debuggers

### Parent Process Check
_Check PPID for debugger_

### Virtual Machine Detection
* Check MAC address for VM prefix
* Registry checks
* Filesystem and VM guest files
* `CPUID` instruction
* Checking device drivers

## Tools
### Wireshark / TCPDump
__Recall how some common queries work__
## Snort IDS
Regex/pattern matching through traffic interception
```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Suspected HTTP C2C Beacon"; 
flow:to_server,established; content:"GET"; http_method; content:"/checkin.php"; http_uri; 
pcre:"/\/checkin\.php\?id=[0-9a-f]{32}&status=ok/i"; 
threshold:type limit, track by_src, count 1, seconds 300; classtype:trojan-activity; sid:1000002; rev:1;)
```

## Debuggers
* Ollydbg
* x64dbg
* dnSpy

## Static Analyzers
* Ghidra
* IDA Pro

### Suricata IDS
Very similar to Snort IDS
```
alert http any any -> any any (msg:"Suspicious C2 User-Agent Detected"; 
flow:established,to_server; content:"GET"; http_method; 
content:"User-Agent|3A| BadBot v1.0"; http_header; classtype:trojan-activity; sid:1000001; rev:1;)
```

### Bro/Zeek
__TODO__

### Palo Alto NGFW
1. **Application-based Policy Enforcement**
    * Identify and control applications on any port, not just by protocol or port
    * App-Id(TM) technology to identify applications
2. **User Identification Controls**
    * User-Id(TM) technology to tie network activity to users, not just IPs
    * Integration with MS AD
3. **Content Inspection and Threat Prevention**
    * Deep packet inspection
4. SSL Decryption/inspection
5. URL filtering based on policy
6. WildFire Malware Analysis
    * Cloud-based service that integrates with the firewall to identify unknown malware, zero-day exploits, and advanced persistent threats (APTs).
    * Automatic sharing of threat intel
7. GlobalProtect(tm) (mobile)
8. PAN-OS (core OS for fw)
9. Advanced Threat Protection and Intelligence
    * Integration with Autofocus(tm) contextual threat intelligence service
10. Cloud integration
11. IoT
12. MFA

### YARA
Example YARA sig matching a particular string
```
rule RuleName {
    meta:
        author = "Author Name"
        description = "Description of the rule"
    strings:
        $string1 = "This is a string"
        $string2 = { E2 34 A1 C8 }
    condition:
        $string1 or $string2
}
```

* Logical operators: and, or, not.
* Count of strings: For instance, #string1 > 2 (meaning string1 should appear more than twice).
* Positional operators: at or in to specify where in the file the strings should appear.
* File size checks: For instance, filesize < 200KB.
* Other YARA-specific functions and keywords, like pe.imphash() for matching specific PE file import hashes.

### Python libraries for automation
`pydbg` Debugging malware
`capstone` Disassembly framework
`pefile` PE executable analysis framework

### Cuckoo Sandbox
Automated malware analysis system, runs in a sandbox and monitors APIs, behaviour and determines IoCs

### Debuggers and Analysis Tools
1. Ollydbg
2. x64dbg
3. dnSpy
4. PEiD
5. CFF Explorer
6. HxD (hex editor)
7. UPX
8. Ghidra
9. IDA
10. VirusTotal

## Attack Vectors (malware)
1. Phishing
2. Spearphishing
3. Drive-by download (i.e. malicious site, email, bla bla)
4. Malvertising (http redirection)
5. Social Engineering (is this really hacking? plz don't pwn me)
6. MitM 
    * Sniffing
    * ARP poisoning
    * mDNS (multicast DNS, which is DNS via broadcast, similar to ARP)
    * DNS Spoofing
    * Packet Injection 
    * Session Hijacking - temporary session tokens that are stolen and reused
    * SSL/TLS stripping, i.e. reducing encryption difficulty
7. USB / reusable media (see stuxnet)
8. Supply chain attacks (hardware or software mods before it reaches consumer)
9. RDP Exploits
10. Botnets (DDoS/DoS)
11. Watering hole attacks (target a specific site or org an infect them all)
12. Fileless malware (see #fileless-malware)
13. Mobile
14. IoT botnets

## Major exploits / vulnerabilities
RDP

## Fileless malware
* Powershell and .NET stagers
* Fileless: meaning all execution ocurrs in memory-only
* Use Powershell, WMI, Office docs, etc to execute code
* LOLBins (Living off the land binaries), that use PS, for example, to install malware or backdoors


## Malicious Techniques
* **DNS Tunneling**
* **Beaconing Intervals** Indicate potential C2 communication

## Detection Techniques
* **Constants or string literals**
* **Hardcoded URIs**
* **Assembler that handles decryption**
* **Assembler that handles API resolution**
* **Specific or Anomalous APIS**


## IOCs (Indicators of Compromise)
* **IP / Domain** Destination
* **URLs** Unusual or anomalous URLSs
* **Checksums/Hashes** that match known payloads
* **Email addresses**
* **Artifacts** Malware mutexes, string constants
* **Network Sigs**
* **System or file modification**
* **Registry**
* **Unusual account behaviour**
* **Unusual DNS requests**
* **Anomalous HTTP requests/responses**

# File Formats
## PE (Portable Executable)
<img src="images/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg">

## ELF (Extensible Linkable Format)
		.bss (rw data, uninitialized)
		.comment (comment section)
		.data & .data1 (rw data, initialized)
		.debug (debug info)
		.fini (finalization instructions)
		.init (runtime initialization)
		.rodata & .rodata1 (ro data)
		.text (executable)
		.line (contains gdb line numbers for debugging)
		.note (notes, etc)

