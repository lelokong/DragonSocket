/*
	DragonSocket
	Simple Web Socket Server

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <vector>
#include "sha1.h"
#include "base64.h"

class DragonSocket             
{
  public:      
    DragonSocket(std::string ipAddressString, std::string portString); 
    ~DragonSocket();   
    void start();
	void stop();
	void send(const char * msg);
	bool isAlive();

 private:        
	std::string ip;
    std::string port;
	int portNumber;
	std::string searchKey;
	
	void active();
	void input(int newsockfd);
	
	std::string handshake(std::string key);
	std::string code(std::string data);
	int mask(const char * message, char * buffer);
	int unmask(const char * data, char * buffer);
	
	std::thread main_thread;
	bool kill_thread;
	
	int sockfd;
	std::vector<int> readfd;
	void destroy_readfd(int fd);
};
/* Constructor */
DragonSocket::DragonSocket(std::string ipAddressString, std::string portString)
{
	ip = ipAddressString;
	port = portString;
	portNumber = atoi(portString.c_str());
	searchKey = "Sec-WebSocket-Key:";
}
 /* Destructor */
DragonSocket::~DragonSocket() 
{
	
}
/* Start Server */
void DragonSocket::start()
{ 
	kill_thread = false;
	main_thread = std::thread (&DragonSocket::active, this);
	main_thread.detach();
}
/* Stop Server */
void DragonSocket::stop()
{
	kill_thread = true;
	for (int i = 0; i < readfd.size(); i++)
		close(readfd[i]);
	readfd.clear();
    close(sockfd);	
}
/* Check Server */
bool DragonSocket::isAlive()
{
	return !kill_thread;
}
/* Send Message */
void DragonSocket::send(const char * msg)
{
	for (int i = 0; i < readfd.size(); i++)
	{
		int fd = readfd[i];
		char hello_buffer[64];
		bzero(hello_buffer, 64);
		int size_buff = mask(msg, hello_buffer); 
			
		if (write(fd, hello_buffer, size_buff) < 0) destroy_readfd(fd);
	}
}
/* Close FD from readfd vector */
void DragonSocket::destroy_readfd(int fd)
{
	for (int i = 0; i < readfd.size(); i++)
	{
		if (readfd[i] = fd)
		{
			close(readfd[i]);
			readfd.erase(readfd.begin() + i);
			return;
		}
	}
}
/*  Active a Server */
void DragonSocket::active()
{
	// Initial Variables
	int newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
	serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portNumber);

	// Open, Bind, and Listen to Socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0 || bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
    {
		stop();
		return;
	}
	listen(sockfd,5);	
	
	// Accept Socket Loop
	clilen = sizeof(cli_addr);
	while (!kill_thread)
	{
		if (readfd.size() < 100) // Limit Max 100 Connections
		{
			newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0)
			{
				stop();
				return;
			}		

			readfd.push_back(newsockfd);
			std::thread (&DragonSocket::input, this, newsockfd).detach();
		}
	}
}
/*  Read Message From Client */
void DragonSocket::input(int newsockfd)
{
	bool handshake_complete = false;
	int n;
	char buffer[1024];
	bzero(buffer, 1024);
    while (!kill_thread && (n = read(newsockfd,buffer,1024)) > 0) 
	{
		std::string hay = buffer;
		if (!handshake_complete)
		{
			std::size_t found = hay.find(searchKey);
			if (found != std::string::npos) 
			{
				std::string key = hay.substr(found + 19, 24);
				key = handshake(key);
			
				n = write(newsockfd, key.c_str(), key.length());
				if (n < 0) break;
				
				handshake_complete = true;
			}
		}
		else
		{		
			char message_buffer[127];
			bzero(message_buffer, 127);
			int size_buff = unmask(hay.c_str(), message_buffer);
			char message[size_buff];
			strncpy(message, message_buffer, size_buff);
			
			// Server Example Stop Command
			std::string stopKey = "stop";
			std::string findKey = message;
			std::size_t found = findKey.find(stopKey);
			if (found != std::string::npos) stop();
		}
	}
	destroy_readfd(newsockfd);
}
/* Handshake Message */
std::string DragonSocket::handshake(std::string key)
{
    std::string result = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n";
    result += "Upgrade: websocket\r\n";
    result += "Connection: Upgrade\r\n";
    result += "WebSocket-Origin: " + ip + "\r\n";
    result += "WebSocket-Location: ws://" + ip + ":" + port + "\r\n";
    result += "Sec-WebSocket-Accept:" + code(key) + "\r\n\r\n";
    return result;
}
/* Encode Key */
std::string DragonSocket::code(std::string key)
{
    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char buffer[20];
	sha1::calc(key.c_str(), key.length(), buffer);
	return base64_encode(buffer, 20);
}
/* Mask Send Message */
int DragonSocket::unmask(const char * message, char * buffer)
{
	int final_size = message[1] & 0x7f;
	char mask[4];
	if (final_size < 125)
	{
		char result[final_size];
		for (int i = 0; i < 4; i ++)
			mask[i] = message[2 + i];
		for (int i = 0; i < final_size; i ++)
			result[i] = message[6 + i];
		for (int i = 0; i < final_size; i++)
			result[i] ^= mask[i % 4];
		strncpy(buffer, result, final_size);
	}
	else if (final_size == 126)
	{
		final_size = (message[2] & 255) << 8;
		final_size |=(message[3] & 255);
		
		char result[final_size];
		for (int i = 0; i < 4; i ++)
			mask[i] = message[4 + i];
		for (int i = 0; i < final_size; i ++)
			result[i] = message[8 + i];
		for (int i = 0; i < final_size; i++)
			result[i] ^= mask[i % 4];
		strncpy(buffer, result, final_size);
	}
	else
		return 0;
	
	return final_size;
}
/* Unmask Receive Message */
int DragonSocket::mask(const char * message, char * buffer)
{
	int size = strlen(message);
	if (size <= 125)
	{
		char result[2 + size];
		result[0] = 0x81;
		result[1] = size;
		for (int i = 0; i < size; i++)
			result[i + 2] = message[i];
		strncpy(buffer, result, 2 + size);
		return strlen(result);
	}
	else if (size >= 126 && size <=  65535)
	{
		char result[4 + size];
		result[0] = 0x81;
		result[1] = 126;
		result[2] = ((size >> 8) & 255);
		result[3] = (size & 255);
		for (int i = 0; i < size; i++)
			result[i + 2] = message[i];
		strncpy(buffer, result, 2 + size);
		return strlen(result);
	}
	return 0;
}