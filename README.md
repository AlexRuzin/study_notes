# Study Notes
My personal study notes that I have been collecting over the years
Version 0.1

# Table of Contents
- [Study Notes](#study-notes)
- [Table of Contents](#table-of-contents)
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
      - [Atomics](#atomics)
        * [Memory Order Symantics](#memory-order-symantics)
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
- [YARA](#yara)
  * [Conditionals](#conditionals)
- [File Formats](#file-formats)
  * [PE (Portable Executable)](#pe--portable-executable-)
  * [ELF (Extensible Linkable Format)](#elf--extensible-linkable-format-)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>



# C++ Programming (the language of the old gods and universe)
__TODO__ Major rewrite of this section


Multi-paradigm language (OOP)
Procedural (C, callback)
Imperative (uses statements to change the state of the program)
Functional
Generic, modular

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
`std::lock_guard` `std::unique_lock` `std::scoped_lock` (C++17)

#### Condition Variables
Condition variables that allow for safe management of `std::thread`

`std::condition_variable`

#### Atomics
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

# YARA
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

## Conditionals
* Logical operators: and, or, not.
* Count of strings: For instance, #string1 > 2 (meaning string1 should appear more than twice).
* Positional operators: at or in to specify where in the file the strings should appear.
* File size checks: For instance, filesize < 200KB.
* Other YARA-specific functions and keywords, like pe.imphash() for matching specific PE file import hashes.

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

