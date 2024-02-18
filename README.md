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



## Other C++ notes
* `vftable` or `vtable` is an array of function pointers that point to the definitions for that particular class