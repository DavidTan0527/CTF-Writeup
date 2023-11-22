#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define INSERT	1
#define ADMIN		2
#define GAMBLE 	3
#define LOG 		4

char *admin_command_page;
int log_fd;

int log_connect();
int log_write(const char *str, ...);
int read_until(char *buf, unsigned int size);
int key_check(char *buf, unsigned int size);
int get_command_internal();
int get_command();
int insert_internal(unsigned int size);
int insert();
void admin();
void gamble();


int log_connect(){
  int ret;
  int port;
  unsigned int size;
  char ip_str[0x100];
  struct sockaddr_in serv_addr;

  printf("Input IP\n");
  fflush(stdout);
  ret = read_until((char *)&size, 4);
  if(size > 0x100){
    printf("size is too big:%x, must be less than %x\n", size, 0x100);
    fflush(stdout);
    return -1;
  }
  if(ret == -1){
    return ret;
  }
  ret = read_until(ip_str, size);
  if(ret == -1){
    return ret;
  }

  printf("Input port\n");
  fflush(stdout);
  ret = read_until((char *)&port, 4);
  if(ret == -01){
    return ret;
  }

  log_fd = socket(AF_INET, SOCK_STREAM, 0);
  if(log_fd < 0){
    printf("log conenct fail\n");
		fflush(stdout);
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  ret = inet_pton(AF_INET, ip_str, &serv_addr.sin_addr);
  if(ret <= 0){
    printf("Invalid address\n");
		fflush(stdout);
    return -1;
  }

  ret = connect(log_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if(ret < 0){
    printf("connection failed\n");
		fflush(stdout);
    return -1;
  }

  log_write("CONNECT\n");
  return 0;
}

int log_write(const char *str, ...){
	int ret;
	char buf[0x1000];
	va_list ap;
	va_start(ap, str);
	ret = vsprintf(buf, str, ap);
	va_end(ap);

	ret = send(log_fd, buf, strlen(buf), 0);
	return ret;
}

int read_until(char *buf, unsigned int size){
	int ret;	
	while(1){
		ret = read(0, buf, size);
		if(ret<=0){
			return -1;
		}
		size -= ret;
		if(size <= 0)
			break;
	}
	return 0;
}

int key_check(char *buf, unsigned int size){
	char *tmp;
	int ret;
	tmp = (char *)malloc(size);
	ret = read_until(tmp, size);
	if(ret==-1)
		return -1;
	ret = memcmp(buf, tmp, size);
	free(tmp);
	if(ret!=0)
		return 0;
	return 1;
}

int get_command_internal(){
	int ret;
	char buf[10];
	ret = read_until(buf, 10);
	if(strcmp(buf, "INSERT")==0){
		return INSERT;
	}else if(strcmp(buf, "ADMIN")==0){
		return ADMIN;
	}else if(strcmp(buf, "GAMBLE")==0){
		return GAMBLE;
	}else if(strcmp(buf, "LOG")==0){
		return LOG;
	}
	return -1;
}

int get_command(){
	int ret;
	int key;
	int fd;
	
	sleep(1);

	ret = get_command_internal();
	if(ret==ADMIN){
		fd = open("key", O_RDONLY);
		read(fd, &key, 4);
		close(fd);
		ret = key_check((char *)&key, 4);
		if(ret==1){
			return ADMIN;
		}else{
			log_write("key is wrong\n");
			return 0;
		}
	}
	return ret;
}

int insert_internal(unsigned int size){
	int ret;
	char *buf;
  buf = admin_command_page;
  ret = read_until(buf, size);
	return ret;
}

int insert(){
	unsigned int size_max;
	unsigned int size;
	int ret;
		
	size_max = 0x1000;
	log_write("Insert Code\n");

	ret = read_until((char *)&size, 4);
	if(size>=size_max){
		log_write("size is too big:%d, must be less than %d\n", size, size_max);
		return -1;
	}
	if(ret == -1){
		return -1;
	}
	ret = insert_internal(size);

	return ret;
}

void admin(){
    log_write("executing\n");
	void (*sc)(void);
	sc = (void (*)(void))admin_command_page;
	sc();
}

void gamble(){
	int fd;
	int ret;
	unsigned int luck;

	sleep(5);
	fd = open("/dev/urandom", O_RDONLY);
	ret = read(fd, &luck, 4);
	if(ret == -1){
		return;
	}
	close(fd);
	if(luck != 777){
		log_write("fail....\n");
		return;
	}
	log_write("lucky!!\n");
	void (*lucky)();
	lucky = (void (*)(void))admin_command_page;
	lucky();
}

int main(){
	int choice;
	int ret;
	admin_command_page =  mmap(0,
       getpagesize(),
       PROT_READ | PROT_WRITE | PROT_EXEC,
       MAP_ANONYMOUS | MAP_PRIVATE,
       0,
       0);
	
	while(1){
		ret = get_command();
		switch(ret){
			case INSERT:
				ret = insert();
				break;
			case ADMIN:
				admin();
				break;
			case GAMBLE:
				gamble();
				break;
			case LOG:
				ret = log_connect();
				break;
			default:
				break;
		}
		if(ret==-1){
			printf("process end\n");
			log_write("process end\n");
			exit(1);
		}
	}
}
