if ! [ -x "$(command -v clang++)" ]; then
    echo '[*] It appears clang++ is not installed on your machine'
    echo '[*] it is recommended to use clang++ for compilation'
    echo '[*] clang++ can be installed via "sudo apt install <package>"'
    exit 2
fi

echo '[*] Attemping to Compile C2 Build. . .'
clang++ -g -Werror -W -Wunused -Wuninitialized -Wshadow -std=c++17 C2.cpp -o server.out
COMPILED=$?

if [ $COMPILED -ne 0 ]; then
    echo '[-] There was an Error during Compiling SORRY! :('
    exit 1
fi

echo '[+] Program Compiled Successfully!'
echo '[*] Execute ./server.out to start up C2-Server!'
exit 0
