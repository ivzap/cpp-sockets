#include "HttpSocket.h"
#include <sys/socket.h>
#include <stdexcept>
#include <netdb.h>
#include <unistd.h>
#include <iostream>
#include <chrono>


/*
    Utility function for displaying a stack trace of the error stack
    in openssl. Useful for debugging purposes.
*/
void openssl_error_stack_bt(FILE* fp){
    int err = 0, i = 0;
    while((err = ERR_get_error())){
        fprintf(fp, "[f=%d] %s\n", i++, ERR_error_string(err, NULL));
    }
}

/*
 *    Utility function for discarding the most recent error on the ssl
 *    error stack. Useful if we dont care about the error.
 */
void openssl_discard_error(SSL *ssl, int ret){
    int err = SSL_get_error(ssl, ret);
    if(err != SSL_ERROR_NONE){
        ERR_get_error();
    }
}

/*
    Returns a integer representing the reason error code. Useful for custom
    error handling control flow and online searches. The input "error" is from a ERR_get_error()
    call.
*/
int openssl_get_error_reason(unsigned long error){
    return ERR_GET_REASON(error);
}

HttpSocket::HttpSocket(){
    ctx = nullptr;
    ssl = nullptr;

    sock = -1;
}

bool HttpSocket::Connect(std::string& hostname, int port){
    if(sock != -1){
        throw std::runtime_error("connect failed: existing connection inplace  -> close connection before connecting.");
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Resolve hostname or IP address
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(hostname.c_str(), port_str.c_str(), &hints, &res);
    if (status != 0) {
        throw std::runtime_error("getaddrinfo failed: " + std::string(gai_strerror(status)));
    }

    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if(sock == -1){
        throw std::runtime_error("socket failed: an error occured while creating the socket.");
    }

    // Establish the connection to the server (TCP)
    if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
        close(sock);
        sock = -1;
        throw std::runtime_error("connect failed: unable to establish the connection to the server.");
    }

    // Establish ssl connection
    const SSL_METHOD* method = TLS_client_method();

    ctx.reset(SSL_CTX_new(method));

    if (!ctx) {
        sock = -1;
        throw std::runtime_error("SSL_CTX_new failed: unable to create SSL context.");
    }

    long options = SSL_CTX_set_options(ctx.get(), SSL_OP_IGNORE_UNEXPECTED_EOF);

    ssl.reset(SSL_new(ctx.get()));

    if (!ssl) {
        ctx.reset();
        sock = -1;
        throw std::runtime_error("SSL_new failed: unable to create SSL structure.");
    }

    // Bind the socket to the SSL object
    if (!SSL_set_fd(ssl.get(), sock)) {
        ctx.reset();
        ssl.reset();
        sock = -1;
        throw std::runtime_error("SSL_set_fd failed: unable to bind socket to SSL.");
    }

    // Perform SSL handshake
    int ssl_result = SSL_connect(ssl.get());
    if (ssl_result <= 0) {
        int err = SSL_get_error(ssl.get(), ssl_result);
        ctx.reset();
        ssl.reset();
        sock = -1;
        throw std::runtime_error("SSL_connect failed: unable to establish SSL connection. Error: " + std::to_string(err));
    }

    struct timeval timeout;
    timeout.tv_sec = DEFAULT_READ_TIMEOUT_SEC;
    timeout.tv_usec = DEFAULT_READ_TIMEOUT_USEC;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    return true;
}

/*
    Sends a request specified by payload and of exactly size bytes. If
    an error is detect it is thrown.
*/
int HttpSocket::Send(const char *payload, int size){
    if(sock == -1){
        throw std::runtime_error("send failed: couldn't send data -> must establish connection first.");
    }

    int bytes_sent = SSL_write(ssl.get(), payload, size);

    if (bytes_sent <= 0) {
        int err = SSL_get_error(ssl.get(), bytes_sent);
        if(err != 0){
            if(err != SSL_ERROR_ZERO_RETURN){
                throw err;
            }
        }
        bytes_sent = 0;
    }

    return bytes_sent;
}

/*
    Reads min(bufferered_size, size) bytes from the socket buffer i.e if
    buffered_size < size we will only read buffered_size bytes. If an error is detected
    it is thrown.
*/
int HttpSocket::Read(char *out, int size){
    if(sock == -1){
        throw std::runtime_error("read failed: couldn't read data from record buffer -> must establish connection first.");
    }

    int bytes_read = SSL_read(ssl.get(), out, size);

    if (bytes_read <= 0) {
        int err = SSL_get_error(ssl.get(), bytes_read);
        if(err != 0){
            if(err != SSL_ERROR_ZERO_RETURN){
                throw err;
            }
        }
        bytes_read = 0;
    }

    return bytes_read;
}

/*
    Closes the socket connection while clearing the ssl read buffer, sending its remaining
    contents to the supplied buffer "out" if needed. Note: if the remaining number of bytes
    exceeds the size provided then out will be treated as a circular buffer (writing wraps back around, overwriting content).
*/
int HttpSocket::Close(char *out, int size){
    if(sock == -1){
        throw std::runtime_error("close failed: couldnt close the socket -> active connection must be in-place.");
    }

    int status = 0;
    if((status = SSL_shutdown(ssl.get())) <=0){
        openssl_discard_error(ssl.get(), status);
    }

    struct timeval timeout;
    socklen_t optlen = sizeof(timeout);
    getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, &optlen);

    int j = 0, bytes_read = 0;
    auto start = std::chrono::high_resolution_clock::now();
    while((bytes_read = SSL_read(ssl.get(), out+j, size-j)) > 0){
        j = (j + bytes_read) % size;
        auto end = std::chrono::high_resolution_clock::now();

        auto elapsed_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        suseconds_t total_us = timeout.tv_sec*1e6 + timeout.tv_usec;

        total_us -= elapsed_time_us;

        timeout.tv_sec = std::max<suseconds_t>(0, total_us / 1000000);
        timeout.tv_usec = std::max<suseconds_t>(0, total_us % 1000000);

        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        start = std::chrono::high_resolution_clock::now();
    }

    if(bytes_read <= 0){
        openssl_discard_error(ssl.get(), bytes_read);
    }

    close(sock);
    sock = -1;

    return j;

}

void HttpSocket::SetReadTimeout(int seconds){
    struct timeval read_timeout;
    read_timeout.tv_sec = seconds;
    read_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&read_timeout, sizeof(read_timeout));
}

void HttpSocket::SetSendTimeout(int seconds){
    struct timeval send_timeout;
    send_timeout.tv_sec = seconds;
    send_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout, sizeof(send_timeout));
}

HttpSocket::~HttpSocket(){
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
}
