/**
  ******************************************************************************
  * @file    hgics.c
  * @author  HUGE-IC Application Team
  * @version V1.0.0
  * @date    2022-05-18
  * @brief   hgic smac driver daemon.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2022 HUGE-IC</center></h2>
  *
  ******************************************************************************
  */

#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "hgic.h"

#include "iwpriv.c"

int main(int argc, char *argv[])
{
    int  fd = -1;
    int  i = 0;
    int  len = 0;
    char cmd[512];
    char *buff;
    int ret = 0;

    if (argc < 2) {
        return -1;
    }

    buff = malloc(4096);
    if (buff == NULL) {
        printf("no mem\r\n");
        return -1;
    }

    fd = open("/proc/hgics/iwpriv", O_RDONLY);
    if (fd != -1) {
        HGIC = "hgics";
    } else {
        fd = open("/proc/hgicf/iwpriv", O_RDONLY);
        if (fd != -1) {
            HGIC = "hgicf";
        } else {
            printf("open iwpriv file fail\r\n");
            free(buff);
            return -1;
        }
    }
    close(fd);

    for (i = 1; i < argc; i++) {
        len += sprintf(cmd + len, "%s ", argv[i]);
    }
    cmd[len - 1] = 0;

    memset(buff, 0, 4096);
    ret = hgic_iwpriv_do(cmd, 0, 0, buff, 4096);
    printf("RESP:%d\r\n%s\r\n", ret, buff);
    free(buff);
    return 0;
}

