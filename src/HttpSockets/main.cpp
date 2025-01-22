#include <iostream>
#include "HttpSocket.h"
#include <cstring>  // For std::strstr

int main(){
    HttpSocket socket;
    std::string hostname = "127.0.0.1";
    char bin[1024] = {0};
    try{
        socket.Connect(hostname, 5000);
    } catch (std::runtime_error& err){
        openssl_error_stack_bt(stdout);
        return 0;
    }
    const char *request = "GET /users/1 HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nConnection: close\r\n\r\n";
    socket.Send(request, strlen(request));
    int i = 0;
    while(socket.Read(bin, 1024)){
        std::cout << "Read#" << i++ << std::endl;
        std::cout << bin << std::endl;
        memset(bin, 0, sizeof(bin));
    }


    socket.Close(bin, 1024);



    return 0;
}
