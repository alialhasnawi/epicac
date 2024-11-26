# epicac

Shared memory IPC.
Implements basic message passing on Windows and POSIX platforms without
using sockets or pipes.
Use it for applications that require communication between separate processes
with a high volume of small messages and low latency such as Electron
desktop applications.

The epicac C library has a low level polling API which can be easily integrated
into programs with a wide variety of I/O and concurrency models.

# Building

The library can be compiled using any compiler supporting C99
on Windows or POSIX platforms.
Just add the source `lib/epicac.c` to your preferred build system
and `lib/epicac.h` to your includes.

For instructions on building the CLI utility `epicat` and
test executables continue reading.

If you are running on a Unix system (or MinGW/Git Bash) with GCC (or a GCC
compatible compiler set by passing `CC=YOUR_FAVOURITE_COMPILER`), just run make.
The Makefile is written with GNU Make in mind.
```
make
# Executables are generated under a build/ directory.
```

## CMake

```
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

To build using MinGW GCC instead of MSVC on Windows:
```
mkdir build
cd build
cmake .. -G "MinGW Makefiles"
cmake --build . --config Release
```

# Tests

Run the test manually:
```
./test_main
./bench
```
or using CMake (will run tests and benchmark):
```
ctest -C Release
```
The benchmark test may fail on MSVC Release builds. There's probably
an issue with the default optimization level for that configuration.