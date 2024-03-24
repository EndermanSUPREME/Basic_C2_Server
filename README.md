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
* Upload/Download
* File creation
* obfuscation
* shell index indentifier

## Still Under Development
There are still some small bugs that are being investigated
through testing the program operates as promised, but patches
are on the way!

## Demo
https://github.com/EndermanSUPREME/Basic_C2_Server/assets/67215373/b70b076f-fa6d-4897-8e36-1852f2f8bbe7

## Usage
To compile this into an executable I used:
`clang++ -g -Werror -W -Wunused -Wuninitialized -Wshadow -std=c++17 C2.cpp -o server.out`
after compiling to run it is a simple `./server.out` and you're ready to go!
