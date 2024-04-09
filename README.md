# Basic_C2_Server
This is a small side project using only C++ to build a basic functional Command &amp; Control Server

## Functions
This C2 Server can:
* Support Multiple Shell Sessions
* Listen on ALL interfaces
* Interact/Remove Sessions via Input
* Basic Script Client to build basic reverse-shell commands
* Run Unix system commands locally when outside shell sessions
* Pop-up Notification when a Shell is possibly Captured

## In Developement
* obfuscation

## Still Under Development
There are still some small bugs that are being investigated
through testing the program operates as promised, but patches
are on the way!

## Demo
https://github.com/EndermanSUPREME/Basic_C2_Server/assets/67215373/9bea9496-7404-4ab7-8042-d9d58a585225

## Usage
To compile this into an executable I used:
`clang++ -g -Werror -W -Wunused -Wuninitialized -Wshadow -std=c++17 C2.cpp -o server.out`
after compiling to run it is a simple `./server.out` and you're ready to go!

There is also a bash script `build.sh` that you can use to also compile this program!
```bash
# Made build.sh an executable & run it
chmod +x build.sh
./build.sh

# If build is successful it will prompt about running the c2 compiled program!
```

## Patches
* Adjusted nc shell output
* Fixed logic errors with shell script file output / executable creation
* Fixed -ip flag logic
* Adjusted flag logic, found bugs spawning in false errors
* -O requires -ip when creating files
* Removed the debug statement showing the command parsing results
* Added output prompt when file creation is successful
* Added Windows based Shell Scripts [includes file creation]
* As a cheat method I used unix python3 -c command to make converting UTF-8 -> UTF-16LE -> Base64 more managable
* Adjusted devices/sessions screen to show details on shell user and OS the session links to
* Added another flag to shutdown c2 server (exit)
* Upload/Download options have been created
