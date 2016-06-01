#if 0 /*
	case $1 in connect) modef=CONNECT ;; bind) modef=BIND ;;
		*) echo "'$1' not 'connect' nor 'bind'"; exit 1 ;; esac
	bn=`basename "$0" .c` tbn=$bn-$1
	DEFS="-D$modef -Dmodule=\"$1\""
	case $2 in dbg) tbn=$tbn-dbg DEFS=$DEFS\ -DDBG; esac
	WARN="-Wall -Wstrict-prototypes -pedantic -Wno-long-long"
	WARN="$WARN -Wcast-align -Wpointer-arith " # -Wfloat-equal #-Werror
	WARN="$WARN -W -Wwrite-strings -Wcast-qual -Wshadow" # -Wconversion
	set -xeu
	exec gcc -std=c99 -shared -fPIC -o $tbn.so "$0" $WARN $DEFS -ldl
	exit
      */
#endif
/*
 * $ ldpreload-ttt.c $
 *
 * Author: Tomi Ollila -- too ät iki piste fi
 *
 *      Copyright (c) 2015 Tomi Ollila
 *          All rights reserved
 *
 * Created: Tue 22 Nov 2011 16:55:43 +0200 too
 * Reorganized: Fri 03 Oct 2014 19:21:19 +0300 too
 * Last modified: Wed 01 Jun 2016 13:18:20 +0300 too
 */

#define VERDATE "1.0 (2015-03-19)"

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/uio.h> // for iovec
#include <dlfcn.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
// consts in sockaddr types were problematic -- i don't understand why ???
#define bind(a,b,c) xbind(a,b,c)
#define connect(a,b,c) xconnect(a,b,c)
#include <sys/socket.h>
#undef bind
#undef connect
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/un.h>

#define null ((void*)0)

#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN

#define IADDR(a,b,c,d) ((in_addr_t)((a << 24) + (b << 16) + (c << 8) + d))
#define IPORT(v) ((in_port_t)(v))
#define A256(a) ((a)<<8)

#elif __BYTE_ORDER == __LITTLE_ENDIAN

#define IADDR(a,b,c,d) ((in_addr_t)(a + (b << 8) + (c << 16) + (d << 24)))
#define IPORT(v) ((in_port_t)(((v) >> 8) | ((v) << 8)))
#define A256(a) (a)

#else
#error unknown ENDIAN
#endif

#if DBG
static const char _vers[] = "ldpreload-ttt-" module  " (dbg) " VERDATE;
#else
static const char _vers[] = "ldpreload-ttt-" module  " " VERDATE;
#endif

#if (__GNUC__ >= 4)
#define GCCATTR_SENTINEL __attribute ((sentinel))
#else
#define GCCATTR_SENTINEL
#endif

#if (__GNUC__ >= 3)
#define GCCATTR_NORETURN __attribute ((noreturn))
#define GCCATTR_UNUSED   __attribute ((unused))
#else
#define GCCATTR_NORETURN
#define GCCATTR_UNUSED
#endif

// (variable) block begin/end -- explicit liveness...
#define BB {
#define BE }

void diev(int ev, ...) GCCATTR_SENTINEL GCCATTR_NORETURN;
void diev(int ev, ...)
{
    struct iovec iov[16];
    va_list ap;

    va_start(ap, ev);
    int i = 0;
    for (char * s = va_arg(ap, char *); s; s = va_arg(ap, char *)) {
        if (i == sizeof iov / sizeof iov[0])
            break;
        iov[i].iov_base = s;
        iov[i].iov_len = strlen(s);
        i++;
    }
    /* for writev(), iov[n].iov_base is const */
    *(const char **)&(iov[i].iov_base) = "\n";
    iov[i].iov_len = 2;
    i++;
    writev(2, iov, i);
    exit(ev);
}

#if DBG || HAVE_U2S
static char * u2s(char * p, unsigned int u) GCCATTR_UNUSED;
static char * u2s(char * p, unsigned int u)
{
    if (u == 0) *p++ = '0';
    else {
	int k = (u > 99999)? 1e9: 10000;
	while (k > 0) {
	    int r = u / k;
	    if (r > 0)
		*p++ = (r % 10) + '0';
	    k /= 10;
	}
    }
    return p;
}
#endif

#if DBG || HAVE_I2S
static char * i2s(char * p, int i) GCCATTR_UNUSED;
static char * i2s(char * p, int i)
{
    if (i < 0) { *p++ = '-'; i = -i; }
    if (i == 0) *p++ = '0';
    else {
	int k = (i > 99999)? 1e9: 10000;
	while (k > 0) {
	    int r = i / k;
	    if (r > 0)
		*p++ = (r % 10) + '0';
	    k /= 10;
	}
    }
    return p;
}
#endif

#if DBG || HAVE_U2X
static char hexchar[16] = "0123456789abcdef";
static char * u2x(char * p, unsigned int x) GCCATTR_UNUSED;
static char * u2x(char * p, unsigned int x)
{
    if (x > 65535) {
	*p++ = hexchar[(x >> 28) & 15];
	*p++ = hexchar[(x >> 24) & 15];
	*p++ = hexchar[(x >> 20) & 15];
	*p++ = hexchar[(x >> 16) & 15];
    }
    *p++ = hexchar[(x >> 12) & 15];
    *p++ = hexchar[(x >> 8) & 15];
    *p++ = hexchar[(x >> 4) & 15];
    *p++ = hexchar[x & 16];
    return p;
}
#endif

#if DBG
#define dz do { char dbuf[256], *dptr = dbuf; int dbgl; (void)dbgl;
#define ds(s) dbgl = strlen(s); memcpy(dptr, s, dbgl); dptr += dbgl;
#define da(a) memcpy(dptr, a, sizeof a - 1); dptr += sizeof a - 1;
#define dc(c) *dptr++ = c;
#define dot *dptr++ = '.';
#define dnl *dptr++ = '\n';
#define du(u) dptr = u2s(dptr, u);
#define di(i) dptr = i2s(dptr, i);
#define dx(x) dptr = u2x(dptr, x);
#define dw write(2, dbuf, dptr - dbuf); } while (0)
#else
#define dz do {
#define ds(s)
#define da(a)
#define dc(c)
#define dot
#define dnl
#define du(u)
#define di(i)
#define dx(x)
#define dw } while (0)

#endif

#if DBG
static void dwritebytes(const char * info, char * p, int l) GCCATTR_UNUSED;
static void dwritebytes(const char * info, char * p, int l)
{
    char buf[3];
    int err = errno;

    write(2, info, strlen(info));

    buf[0] = ' ';
    while (l--)
    {
	if (0 && *p > 32 && *p < 127)
	{
	    buf[1] = *p++;
	    write(2, buf, 2);
	    continue;
	}
	buf[1] = hexchar[(*p>>4) & 0xf];
	buf[2] = hexchar[*p++ & 0xf];
	write(2, buf, 3);
    }
    write(2, "\n", 1);
    errno = err;
}
#else
#define dwritebytes(i, p, l) do {} while (0)
#endif


static void * dlsym_next(const char * symbol)
{
    void * sym = dlsym(RTLD_NEXT, symbol);
    char * str = dlerror();

    if (str != null)
        diev(1, "finding symbol '", symbol, "' failed: ", str, null);

    return sym;
}
#define set_next(name) *(void**)(&name##_next) = dlsym_next(#name)

static char * upath = null;
static int upath_len = -1;

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

static const char * set_upath(void)
{
    if (upath_len >= 0) return upath;
    upath = getenv("I2U_PATH");
    if (upath == null || upath[0] == '\0') return null;

    upath_len = strlen(upath);
    if (upath_len >= UNIX_PATH_MAX)
	diev(1, "I2U_PATH '", upath, "' too long", null);

    if (upath[0] == '@') upath[0] = '\0';

    return upath;
}

#if BIND

#if CONNECT
#error Both BIND and CONNECT defined.
#endif

int bind(int sd, struct sockaddr * addr, socklen_t addrlen)
{
    static int (*bind_next)(int, const struct sockaddr *, socklen_t) = null;
    static int i2uport;
    if (! bind_next)
    {
	set_next(bind);
	char * str;

	if (set_upath() == null)
	    diev(1, "I2U_PATH env var missing (or value empty)", null);

	if ((str = getenv("I2U_PORT")) == null)
	    diev(1, "I2U_PORT env var missing", null);
	if ((i2uport = atoi(str)) <= 0)
	    diev(1, "I2U_PORT env var '", str, "' invalid", null);
    }

    if (((struct sockaddr_in*)addr)->sin_addr.s_addr != IADDR( 127,0,0,1 )
	&& ((struct sockaddr_in*)addr)->sin_addr.s_addr != 0)
	goto _next;

    if (addr->sa_family != AF_INET)
	goto _next;

    int type = -1;
    socklen_t typelen = sizeof type;
    (void)getsockopt(sd, SOL_SOCKET, SO_TYPE, &type, &typelen);
    if (type != SOCK_STREAM)
	goto _next;

    in_port_t port = IPORT(((struct sockaddr_in*)addr)->sin_port);
    if (port != i2uport)
	goto _next;

    /* XXX fcntl flags (like non-blockingness...) */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0)
	return -1;
    dup2(s, sd);
    close(s);

    s = 1; setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &s, sizeof s);

    struct sockaddr_un uaddr = {
	.sun_family = AF_UNIX
    };
    memcpy(uaddr.sun_path, upath, upath_len);

    /* do not unlink upath above -- use shell script to do that */

    return bind_next(sd, (struct sockaddr *)&uaddr, sizeof uaddr);
_next:
    return bind_next(sd, addr, addrlen);
}

#elif CONNECT

/* wait up to 5000 ms ... */
static int pollthis(int fd, int event)
{
    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = event;

    if (poll(&pfd, 1, 500) <= 0) /* Some EINTR protection */
	if (poll(NULL, 0, 200), poll(&pfd, 1, 4300) <= 0)
	{
	    dz da("poll errno: ") di(errno) dnl dw;
	    errno = EIO;
	    return -1;
	}

    return 1;
}

/* itoa(), except backwards (args and output), for unsigned and only base 10 */
static inline int _utosb(char buf[12], unsigned int i)
{
    char * out = buf;

    do { *(out++) = "0123456789"[ i % 10 ]; i /= 10; } while ( i );
    /**out = '\0';*/

    /*puts(buf); */
    return out - buf;
}

/* unsigned int to string, not nul-terminated */
static int utos_nnt(char * p, unsigned int i)
{
    char buf[12];
    char * q;
    int l = _utosb(buf, i);
    int rv = l;
    q = buf + l - 1;
    while (l--) *p++ = *q--;
    return rv;
}

int connect(int sd, struct sockaddr * addr, socklen_t addrlen)
{
    static int (*connect_next)(int, struct sockaddr *, socklen_t) = null;
    static int i2uport;
    static struct sockaddr_in socks4_addr;
    static struct sockaddr_in https_addr;
    if (! connect_next)
    {
	set_next(connect);

	set_upath();

	char * str = getenv("I2U_PORT");
	if (str && str[0] != '\0') {
	    i2uport = atoi(str);
	    if (i2uport <= 0)
		diev(1, "I2U_PORT env var '", str, "' invalid", null);
	    i2uport = IPORT(i2uport);
	}
	else {
	    upath = null;
	    i2uport = 0; // variable unused in this case, avoid compiler warnigs
	}

	memset(&socks4_addr, 0, sizeof socks4_addr);
	str = getenv("SOCKS4_IP");
	if (str && str[0] != '\0') {
	    if (inet_aton(str, &socks4_addr.sin_addr) == 0)
		diev(1, "SOCKS4_IP address '", str, "' incorrect", null);
	    str = getenv("SOCKS4_PORT");
	    if (str && str[0] != '\0') {
		int port = atoi(str);
		if (port <= 1 || port > 65535)
		    diev(1, "SOCKS4_PORT '", str, "' incorrect", null);
		socks4_addr.sin_family = AF_INET;
		socks4_addr.sin_port = IPORT(port);
	    }
	}
	memset(&https_addr, 0, sizeof https_addr);
	str = getenv("HTTPS_IP");
	if (str && str[0] != '\0') {
	    if (inet_aton(str, &https_addr.sin_addr) == 0)
		diev(1, "HTTPS_IP address '", str, "' incorrect", null);
	    str = getenv("HTTPS_PORT");
	    if (str && str[0] != '\0') {
		int port = atoi(str);
		if (port <= 1 || port > 65535)
		    diev(1, "HTTPS_PORT '", str, "' incorrect", null);
		https_addr.sin_port = IPORT(port);
	    }
	    https_addr.sin_family = AF_INET;
	}
    }
#if DBG
    if (addr->sa_family == AF_INET) {
	const unsigned char * s =
	    (unsigned char *)&(((struct sockaddr_in *)addr)->sin_addr);
	dz  da("IP: ") du(s[0]) dot du(s[1]) dot du(s[2]) dot du(s[3])
	    da(", PORT: ") du(IPORT(((struct sockaddr_in*)addr)->sin_port))
	    da("\n") dw;
    }
#endif
    if (addr->sa_family != AF_INET)
	return connect_next(sd, addr, addrlen);
    BB;
    int type = -1;
    socklen_t typelen = sizeof type;
    (void)getsockopt(sd, SOL_SOCKET, SO_TYPE, &type, &typelen);
    if (type != SOCK_STREAM)
	return connect_next(sd, addr, addrlen);
    BE;
    // keep dns queries "local" //
    if (((struct sockaddr_in*)addr)->sin_port == IPORT(53))
	return connect_next(sd, addr, addrlen);

    struct sockaddr_in ia;
    struct sockaddr * a = addr;
    int cont = 0;
    if (socks4_addr.sin_port != 0) {
	// range check, and how it affects...
	memcpy(&ia, &socks4_addr, sizeof ia); // XXX check if can be dropped
	a = (struct sockaddr *)&ia;
	cont = 1;
    }
    else if (https_addr.sin_port != 0) {
	// range? (or comparable) checking here too ?
	memcpy(&ia, &https_addr, sizeof ia); // XXX ditto
	a = (struct sockaddr *)&ia;
	cont = 1;
    }

    long sdflags_orig = fcntl(sd, F_GETFL);
    long sdflags_curr = sdflags_orig;
    struct sockaddr_un uaddr;

    if (upath &&
	/* currently no AF_INET6 support ... */
	((struct sockaddr_in*)a)->sin_addr.s_addr == IADDR( 127,0,0,1 )
	&& ((struct sockaddr_in*)a)->sin_port == i2uport )
    {
	dz da("inet to unix port '") ds(upath) da("'\n") dw;

	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
	    return -1;
	dup2(s, sd);
	close(s);

	memset(&uaddr, 0, sizeof uaddr);
	uaddr.sun_family = AF_UNIX;
	memcpy(uaddr.sun_path, upath, upath_len);
	a = (struct sockaddr *)&uaddr;
	addrlen = sizeof uaddr;

	sdflags_curr = fcntl(sd, F_GETFL);
	dz da("fcntl: ") dx(sdflags_curr) dnl dw;
    }
    if (cont) {
	if (sdflags_curr & O_NONBLOCK) {
	    dz da("disable nonblock onblock\n") dw;
	    sdflags_curr &= ~O_NONBLOCK;
	    (void)fcntl(sd, F_SETFL, sdflags_curr);
	}
#if 0	/* not needed now, for possible future reference */
	if (flarg & O_ASYNC) {
	    dz da("async\n") dw;
	    fpid = fcntl(sd, F_GETOWN);
	}
#endif
    }
    else {
	if (sdflags_curr != sdflags_orig)
	    (void)fcntl(sd, F_SETFL, sdflags_orig);
	return connect_next(sd, a, addrlen);
    }
    int rv = connect_next(sd, a, addrlen);
    if (rv < 0) return rv;

    if (socks4_addr.sin_port != 0) {
	char buf[12];
	buf[0] = 0x04; /* socks 4 */
	buf[1] = 0x01; /* connect */

	/* port. 2 bytes. network byte order */
	memcpy(&buf[2], &((struct sockaddr_in*)addr)->sin_port, 2);
	/* ip. 4 bytes. network byte order */
	memcpy(&buf[4], &((struct sockaddr_in *)addr)->sin_addr.s_addr, 4);

	buf[8] = 'w';  /* any string */
	buf[9] = '\0';

	dwritebytes("socks ->", buf, 10);

	/* We trust socket buffer can consume 10 bytes at the beginning... */
	if (write(sd, buf, 10) != 10)
	    goto _nogo;

	int l = 0;
	while (pollthis(sd, POLLIN) > 0) {
	    int i = read(sd, buf + l, 8 - l);

	    if (i <= 0) {
		goto _nogo;
		/*errno = ECONNREFUSED; */
	    }
	    l += i;

	    if (l == 8) {
		dwritebytes("socks <-", buf, 8);
		if (buf[0] == 0 && buf[1] == 90) {
		    rv = 0;
		    goto _end;
		}
		else
		    l = 0; /* XXX ??? */
	    }
	}
    }

    else if (https_addr.sin_port != 0) {
	struct iovec iov[3];
	char buf[256];
	int pos;
	unsigned char * addrbytes
	    = (unsigned char *)&((struct sockaddr_in *)addr)->sin_addr.s_addr;

	/* request:  "CONNECT <remotehost>[:<port>] HTTP/1.1\r\n\r\n"
	   response: "HTTP/1.1 200 Connection established\r\n[...\r\n]\r\n" */

	/* for writev(), iov[n].iov_base is const */
	*(const char **)&(iov[0].iov_base) = "CONNECT ";
	iov[0].iov_len = 8;

	int port = IPORT(((struct sockaddr_in*)addr)->sin_port);

	iov[1].iov_base = buf;
	pos = utos_nnt(buf, addrbytes[0]);         buf[pos++] = '.';
	pos += utos_nnt(buf + pos, addrbytes[1]);  buf[pos++] = '.';
	pos += utos_nnt(buf + pos, addrbytes[2]);  buf[pos++] = '.';
	pos += utos_nnt(buf + pos, addrbytes[3]);  buf[pos++] = ':';
	pos += utos_nnt(buf + pos, port);
	iov[1].iov_len = pos;

	*(const char **)&(iov[2].iov_base) = " HTTP/1.1\r\n\r\n";
	iov[2].iov_len = 13;

	/* XXX check return value (adds up to iov_lens) */
	writev(sd, iov, 3);

	dwritebytes("CONNECT request ->", iov[1].iov_base, iov[1].iov_len);

	/* response must come in period short enough */
	if (pollthis(sd, POLLIN) < 0)
	    goto _nogo;

	int l, x = 0;
	while ((l = recv(sd, buf, sizeof buf, MSG_PEEK)) > 0) {
	    dwritebytes("CONNECT reply <-", buf, l);

	    if (l == sizeof buf)
		goto _nogo;

	    for (int i = 0; i < l; i++) {
		/* XXX add loop counter, so don't try forever */
		/* alternatively, consume up and do normal poll */
		if (buf[i] == '\n') {
		    if (x)
			/* consume reply out of socket buffer */
			if (recv(sd, buf, i+1, 0) == i+1) {
			    rv = 0;
			    goto _end;
			}
			else goto _nogo;
		    else
			x = 1;
		}
		else if (buf[i] != '\r')
		    x = 0;
	    }
	    /* setting up SIGIO for edge triggered events is too problematic */
	    poll(0, 0, 200);
	}
    }
    else {} // should not get here //
_nogo:
    rv = -1;
    shutdown(sd, 2);
_end:
    if (sdflags_curr != sdflags_orig)
	(void)fcntl(sd, F_SETFL, sdflags_orig);
    return rv;
}

#else
#error Neither BIND nor CONNECT defined.
#endif
