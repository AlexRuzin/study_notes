# Study Notes
My personal study notes that I have been collecting over the years
Version 0.1


# C++ Programming
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
*See `umsignal.h` for a good example of this
Do not forget `std::unique_lock`, at end of scope, release an `std::mutex`
`std::unique_lock<std::mutex> mlock(rpcIoSync);`
#### Headers
`
<thread>
<mutex>
<future>
<atomic>
<condition_variable>
`

#### Thread objects
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

_TODO_
Livelock
Starvation
Locality

# Windows Programming and APIs

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

Useful in debugging and logging:
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

## Generators
Used in parsing large files, CSV, data streams, etc
Function that returns a *lazy iterator*

## Other language notes
* Global Interface Lock (GIL): Automatic object locking (mutex) for objects



# File Formats
# PE (Portable Executable)
# ELF (Extensible Linkable Format)
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
