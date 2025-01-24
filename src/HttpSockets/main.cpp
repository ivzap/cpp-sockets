#include <iostream>
#include "HttpSocket.h"
#include <cstring>  // For std::strstr
#include <thread>
#include <unistd.h> // For sleep() function

int main(){
    HttpSocket socket;
    std::string hostname = "127.0.0.1";
    char bin[SSL_MAX_RECORD_SIZE] = {0};

    socket.Connect(hostname, 8000);
    char *request = "GET /users/1 HTTP/1.1\r\n"
                    "Host: 127.0.0.1:8000\r\n"
                    "Connection: keep-alive\r\n\r\n";


    for(int i = 0; i < 10; i++){
        socket.Send(request, strlen(request));
    }

    int b = 1;
    // while(b){
    //     try{
    //         b = socket.Read(bin, SSL_MAX_RECORD_SIZE);
    //
    //     } catch (int err){
    //         if(err == SSL_ERROR_WANT_READ){
    //             std::cout << "increasing timeout" << std::endl;
    //             // socket.SetReadTimeout(12);
    //         } else {
    //             break;
    //         }
    //     }
    //     std::cout << bin << std::endl;
    //     memset(bin, 0, sizeof(bin));
    // }

    std::this_thread::sleep_for(std::chrono::seconds(4));


    char save[1000000] = {0};

    int bytes_read_after_close = socket.Close(save, 1000000);

    std::cout << "Bytes read after close=" << bytes_read_after_close << std::endl;

    std::cout << save << std::endl;


    return 0;
}
