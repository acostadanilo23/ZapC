#include "zapc/transport.h"
#include "zapc/log.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int tcp_wait(int fd, int events, int timeout_ms)
{
    struct pollfd p;
    p.fd = fd;
    p.events = (short)(((events & 1) ? POLLIN : 0) | ((events & 2) ? POLLOUT : 0));
    p.revents = 0;
    for (;;) {
        int r = poll(&p, 1, timeout_ms);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return -1;
        if (r == 0)
            return 0;
        if (p.revents & (POLLERR | POLLNVAL))
            return -1;
        return 1;
    }
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int tcp_connect(const char *host, uint16_t port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL;
    char portstr[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%u", (unsigned)port);
    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) {
        LOGE("tcp", "cannot resolve %s: %s", host, gai_strerror(gai));
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (set_nonblock(fd) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS) {
            if (tcp_wait(fd, 2, timeout_ms) == 1) {
                int err = 0;
                socklen_t len = sizeof err;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 &&
                    err == 0)
                    r = 0;
                else
                    errno = err;
            } else {
                errno = ETIMEDOUT;
            }
        }
        if (r == 0)
            break;
        LOGD("tcp", "connect attempt failed: %s", strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        LOGE("tcp", "cannot connect to %s:%u", host, (unsigned)port);
        return -1;
    }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    LOGD("tcp", "connected to %s:%u", host, (unsigned)port);
    return fd;
}

void tcp_close(int fd)
{
    if (fd >= 0)
        close(fd);
}

static long tcp_read_cb(void *ctx, void *buf, size_t len)
{
    int fd = *(int *)ctx;
    for (;;) {
        ssize_t n = recv(fd, buf, len, 0);
        if (n >= 0)
            return (long)n;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return ZC_IO_AGAIN;
        return ZC_IO_ERROR;
    }
}

static long tcp_write_cb(void *ctx, const void *buf, size_t len)
{
    int fd = *(int *)ctx;
    const uint8_t *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (tcp_wait(fd, 2, 30000) != 1)
                    return ZC_IO_ERROR;
                continue;
            }
            return ZC_IO_ERROR;
        }
        p += n;
        left -= (size_t)n;
    }
    return (long)len;
}

static size_t tcp_pending_cb(void *ctx)
{
    (void)ctx;
    return 0;
}

zc_stream tcp_stream(int *fd)
{
    zc_stream s;
    s.ctx = fd;
    s.fd = *fd;
    s.read = tcp_read_cb;
    s.write = tcp_write_cb;
    s.pending = tcp_pending_cb;
    return s;
}
