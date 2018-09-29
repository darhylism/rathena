// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "socket.hpp"

#include <stdlib.h>

#ifdef WIN32
	#include "winapi.hpp"
#else
	#include <errno.h>
#include <netinet/tcp.h>
	#include <net/if.h>
	#include <unistd.h>
#include <sys/ioctl.h>
	#include <netdb.h>
	#include <arpa/inet.h>

	#ifndef SIOCGIFCONF
	#include <sys/sockio.h> // SIOCGIFCONF on Solaris, maybe others? [Shinomori]
	#endif
	#ifndef FIONBIO
	#include <sys/filio.h> // FIONBIO on Solaris [FlavioJS]
	#endif

	#ifdef HAVE_SETRLIMIT
	#include <sys/resource.h>
	#endif
#endif

#include "cbasetypes.hpp"
#include "malloc.hpp"
#include "mmo.hpp"
#include "showmsg.hpp"
#include "strlib.hpp"
#include "timer.hpp"

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// global array of sockets (emulating linux)
// fd is the position in the array
static SOCKET sock_arr[FD_SETSIZE];
static int sock_arr_len = 0;

/// Returns the socket associated with the target fd.
///
/// @param fd Target fd.
/// @return Socket
#define fd2sock(fd) sock_arr[fd]

/// Returns the first fd associated with the socket.
/// Returns -1 if the socket is not found.
///
/// @param s Socket
/// @return Fd or -1
int sock2fd(SOCKET s)
{
	int fd;

	// search for the socket
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == s )
			break;// found the socket
	if( fd == sock_arr_len )
		return -1;// not found
	return fd;
}


/// Inserts the socket into the global array of sockets.
/// Returns a new fd associated with the socket.
/// If there are too many sockets it closes the socket, sets an error and
//  returns -1 instead.
/// Since fd 0 is reserved, it returns values in the range [1,FD_SETSIZE[.
///
/// @param s Socket
/// @return New fd or -1
int sock2newfd(SOCKET s)
{
	int fd;

	// find an empty position
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == INVALID_SOCKET )
			break;// empty position
	if( fd == ARRAYLENGTH(sock_arr) )
	{// too many sockets
		closesocket(s);
		WSASetLastError(WSAEMFILE);
		return -1;
	}
	sock_arr[fd] = s;
	if( sock_arr_len <= fd )
		sock_arr_len = fd+1;
	return fd;
}

int sAccept(int fd, struct sockaddr* addr, int* addrlen)
{
	SOCKET s;

	// accept connection
	s = accept(fd2sock(fd), addr, addrlen);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

int sClose(int fd)
{
	int ret = closesocket(fd2sock(fd));
	fd2sock(fd) = INVALID_SOCKET;
	return ret;
}

int sSocket(int af, int type, int protocol)
{
	SOCKET s;

	// create socket
	s = socket(af,type,protocol);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

char* sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

#define sBind(fd,name,namelen) bind(fd2sock(fd),name,namelen)
#define sConnect(fd,name,namelen) connect(fd2sock(fd),name,namelen)
#define sIoctl(fd,cmd,argp) ioctlsocket(fd2sock(fd),cmd,argp)
#define sListen(fd,backlog) listen(fd2sock(fd),backlog)
#define sRecv(fd,buf,len,flags) recv(fd2sock(fd),buf,len,flags)
#define sSelect select
#define sSend(fd,buf,len,flags) send(fd2sock(fd),buf,len,flags)
#define sSetsockopt(fd,level,optname,optval,optlen) setsockopt(fd2sock(fd),level,optname,optval,optlen)
#define sShutdown(fd,how) shutdown(fd2sock(fd),how)
#define sFD_SET(fd,set) FD_SET(fd2sock(fd),set)
#define sFD_CLR(fd,set) FD_CLR(fd2sock(fd),set)
#define sFD_ISSET(fd,set) FD_ISSET(fd2sock(fd),set)
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#else
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif
/////////////////////////////////////////////////////////////////////

#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
#endif

fd_set readfds;
int fd_max;
time_t last_tick;
time_t stall_time = 60;

uint32 addr_[16];   // ip addresses of local host (host byte order)
int naddr_ = 0;   // # of ip addresses

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
#if PACKETVER < 20131223
static size_t socket_max_client_packet = 0x6000;
#else
static size_t socket_max_client_packet = USHRT_MAX;
#endif

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

struct socket_data* session[FD_SETSIZE];

#ifdef SEND_SHORTLIST
int send_shortlist_array[FD_SETSIZE];// we only support FD_SETSIZE sockets, limit the array to that
size_t send_shortlist_count = 0;// how many fd's are in the shortlist
uint32 send_shortlist_set[(FD_SETSIZE+31)/32];// to know if specific fd's are already in the shortlist
#endif

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse);

#ifndef MINICORE
	int ip_rules = 1;
	static int connect_check(uint32 ip);
#endif

const char* error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/*======================================
 *	CORE : Default processing functions
 *--------------------------------------*/
int null_recv(int fd) { return 0; }
int null_send(int fd) { return 0; }
int null_parse(int fd) { return 0; }

ParseFunc default_func_parse = null_parse;

void set_defaultparse(ParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}


/*======================================
 *	CORE : Socket options
 *--------------------------------------*/
void set_nonblocking(int fd, unsigned long yes)
{
	// FIONBIO Use with a nonzero argp parameter to enable the nonblocking mode of socket s.
	// The argp parameter is zero if nonblocking is to be disabled.
	if( sIoctl(fd, FIONBIO, &yes) != 0 )
		ShowError("set_nonblocking: Failed to set socket #%d to non-blocking mode (%s) - Please report this!!!\n", fd, error_msg());
}

void setsocketopts(int fd,int delay_timeout){
	int yes = 1; // reuse fix

#if !defined(WIN32)
	// set SO_REAUSEADDR to true, unix only. on windows this option causes
	// the previous owner of the socket to give up, which is not desirable
	// in most cases, neither compatible with unix.
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&yes,sizeof(yes));
#ifdef SO_REUSEPORT
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEPORT,(char *)&yes,sizeof(yes));
#endif
#endif

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	sSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(https://msdn.microsoft.com/en-us/library/windows/desktop/ms737582%28v=vs.85%29.aspx)
	{
		struct linger opt;
		opt.l_onoff = 0; // SO_DONTLINGER
		opt.l_linger = 0; // Do not care
		if( sSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&opt, sizeof(opt)) )
			ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection #%d!\n", fd);
	}
	if(delay_timeout){
#if defined(WIN32)
		int timeout = delay_timeout * 1000;
#else
		struct timeval timeout;
		timeout.tv_sec = delay_timeout;
		timeout.tv_usec = 0;
#endif

		if (sSetsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_RCVTIMEO timeout for connection #%d!\n");
		if (sSetsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_SNDTIMEO timeout for connection #%d!\n");
	}
}

/*======================================
 *	CORE : Socket Sub Function
 *--------------------------------------*/
void set_eof(int fd)
{
	if( session_isActive(fd) )
	{
#ifdef SEND_SHORTLIST
		// Add this socket to the shortlist for eof handling.
		send_shortlist_add_fd(fd);
#endif
		session[fd]->flag.eof = 1;
	}
}

int recv_to_fifo(int fd)
{
	int len;

	if( !session_isActive(fd) )
		return -1;

	len = sRecv(fd, (char *) session[fd]->rdata + session[fd]->rdata_size, (int)RFIFOSPACE(fd), 0);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("recv_to_fifo: %s, closing connection #%d\n", error_msg(), fd);
			set_eof(fd);
		}
		return 0;
	}

	if( len == 0 )
	{//Normal connection end.
		set_eof(fd);
		return 0;
	}

	session[fd]->rdata_size += len;
	session[fd]->rdata_tick = last_tick;
#ifdef SHOW_SERVER_STATS
	socket_data_i += len;
	socket_data_qi += len;
	if (!session[fd]->flag.server)
	{
		socket_data_ci += len;
	}
#endif
	return 0;
}

int send_from_fifo(int fd)
{
	int len;

	if( !session_isValid(fd) )
		return -1;

	if( session[fd]->wdata_size == 0 )
		return 0; // nothing to send

	len = sSend(fd, (const char *) session[fd]->wdata, (int)session[fd]->wdata_size, MSG_NOSIGNAL);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("send_from_fifo: %s, ending connection #%d\n", error_msg(), fd);
#ifdef SHOW_SERVER_STATS
			socket_data_qo -= session[fd]->wdata_size;
#endif
			session[fd]->wdata_size = 0; //Clear the send queue as we can't send anymore. [Skotlex]
			set_eof(fd);
		}
		return 0;
	}

	if( len > 0 )
	{
		// some data could not be transferred?
		// shift unsent data to the beginning of the queue
		if( (size_t)len < session[fd]->wdata_size )
			memmove(session[fd]->wdata, session[fd]->wdata + len, session[fd]->wdata_size - len);

		session[fd]->wdata_size -= len;
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if (!session[fd]->flag.server)
		{
			socket_data_co += len;
		}
#endif
	}

	return 0;
}

/// Best effort - there's no warranty that the data will be sent.
void flush_fifo(int fd)
{
	if(session[fd] != NULL)
		session[fd]->func_send(fd);
}

void flush_fifos(void)
{
	int i;
	for(i = 1; i < fd_max; i++)
		flush_fifo(i);
}

/*======================================
 *	CORE : Connection functions
 *--------------------------------------*/
int connect_client(int listen_fd)
{
	int fd;
	struct sockaddr_in client_address;
	socklen_t len;

	len = sizeof(client_address);

	fd = sAccept(listen_fd, (struct sockaddr*)&client_address, &len);
	if ( fd == -1 ) {
		ShowError("connect_client: accept failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("connect_client: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("connect_client: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

#ifndef MINICORE
	if( ip_rules && !connect_check(ntohl(client_address.sin_addr.s_addr)) ) {
		do_close(fd);
		return -1;
	}
#endif

	if( fd_max <= fd ) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);

	return fd;
}

int make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if( fd == -1 )
	{
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		exit(EXIT_FAILURE);
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_listen_bind: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_listen_bind: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	result = sBind(fd, (struct sockaddr*)&server_address, sizeof(server_address));
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: bind failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}
	result = sListen(fd,5);
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: listen failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}

	if(fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd, &readfds);

	create_session(fd, connect_client, null_send, null_parse);
	session[fd]->client_addr = 0; // just listens
	session[fd]->rdata_tick = 0; // disable timeouts on this socket

	return fd;
}

int make_connection(uint32 ip, uint16 port, bool silent,int timeout) {
	struct sockaddr_in remote_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if (fd == -1) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_connection: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_connection: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,timeout);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if( !silent )
		ShowStatus("Connecting to %d.%d.%d.%d:%i\n", CONVIP(ip), port);
#ifdef WIN32
	// On Windows we have to set the socket non-blocking before the connection to make timeout work. [Lemongrass]
	set_nonblocking(fd, 1);

	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));

	// Only enter if a socket error occurred
	// Create a pseudo scope to be able to break out in case of successful connection
	while( result == SOCKET_ERROR ) {
		// Specially handle the error number for connection attempts that would block, because we want to use a timeout
		if( sErrno == S_EWOULDBLOCK ){
			fd_set writeSet;
			struct timeval tv;

			sFD_ZERO(&writeSet);
			sFD_SET(fd,&writeSet);

			tv.tv_sec = timeout;
			tv.tv_usec = 0;

			result = sSelect(0, NULL, &writeSet, NULL, &tv);

			// Connection attempt timed out
			if( result == 0 ){
				if( !silent ){
					// Needs special handling, because it does not set an error code and therefore does not provide an error message from the API
					ShowError("make_connection: connection failed (socket #%d, timeout after %ds)!\n", fd, timeout);
				}

				do_close(fd);
				return -1;
			// If the select operation did not return an error
			}else if( result != SOCKET_ERROR ){
				// Check if it is really writeable
				if( sFD_ISSET(fd, &writeSet) != 0 ){
					// Our socket is writeable now => we have connected successfully
					break; // leave the pseudo scope
				}

				if( !silent ){
					// Needs special handling, because it does not set an error code and therefore does not provide an error message from the API
					ShowError("make_connection: connection failed (socket #%d, not writeable)!\n", fd);
				}

				do_close(fd);
				return -1;
			}
			// The select operation failed
		}

		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());

		do_close(fd);
		return -1;
	}
	// Keep the socket in non-blocking mode, since we would set it to non-blocking here on unix. [Lemongrass]
#else
	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));
	if( result == SOCKET_ERROR ) {
		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());
		do_close(fd);
		return -1;
	}

	//Now the socket can be made non-blocking. [Skotlex]
	set_nonblocking(fd, 1);
#endif

	if (fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(remote_address.sin_addr.s_addr);

	return fd;
}

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse)
{
	CREATE(session[fd], struct socket_data, 1);
	CREATE(session[fd]->rdata, unsigned char, RFIFO_SIZE);
	CREATE(session[fd]->wdata, unsigned char, WFIFO_SIZE);
	session[fd]->max_rdata  = RFIFO_SIZE;
	session[fd]->max_wdata  = WFIFO_SIZE;
	session[fd]->func_recv  = func_recv;
	session[fd]->func_send  = func_send;
	session[fd]->func_parse = func_parse;
	session[fd]->rdata_tick = last_tick;
	return 0;
}

static void delete_session(int fd)
{
	if( session_isValid(fd) )
	{
#ifdef SHOW_SERVER_STATS
		socket_data_qi -= session[fd]->rdata_size - session[fd]->rdata_pos;
		socket_data_qo -= session[fd]->wdata_size;
#endif
		aFree(session[fd]->rdata);
		aFree(session[fd]->wdata);
		aFree(session[fd]->session_data);
		aFree(session[fd]);
		session[fd] = NULL;
	}
}

int realloc_fifo(int fd, unsigned int rfifo_size, unsigned int wfifo_size)
{
	if( !session_isValid(fd) )
		return 0;

	if( session[fd]->max_rdata != rfifo_size && session[fd]->rdata_size < rfifo_size) {
		RECREATE(session[fd]->rdata, unsigned char, rfifo_size);
		session[fd]->max_rdata  = rfifo_size;
	}

	if( session[fd]->max_wdata != wfifo_size && session[fd]->wdata_size < wfifo_size) {
		RECREATE(session[fd]->wdata, unsigned char, wfifo_size);
		session[fd]->max_wdata  = wfifo_size;
	}
	return 0;
}

int realloc_writefifo(int fd, size_t addition)
{
	size_t newsize;

	if( !session_isValid(fd) ) // might not happen
		return 0;

	if( session[fd]->wdata_size + addition  > session[fd]->max_wdata )
	{	// grow rule; grow in multiples of WFIFO_SIZE
		newsize = WFIFO_SIZE;
		while( session[fd]->wdata_size + addition > newsize ) newsize += WFIFO_SIZE;
	}
	else
	if( session[fd]->max_wdata >= (size_t)2*(session[fd]->flag.server?FIFOSIZE_SERVERLINK:WFIFO_SIZE)
		&& (session[fd]->wdata_size+addition)*4 < session[fd]->max_wdata )
	{	// shrink rule, shrink by 2 when only a quarter of the fifo is used, don't shrink below nominal size.
		newsize = session[fd]->max_wdata / 2;
	}
	else // no change
		return 0;

	RECREATE(session[fd]->wdata, unsigned char, newsize);
	session[fd]->max_wdata  = newsize;

	return 0;
}

/// advance the RFIFO cursor (marking 'len' bytes as processed)
int RFIFOSKIP(int fd, size_t len)
{
    struct socket_data *s;

	if ( !session_isActive(fd) )
		return 0;

	s = session[fd];

	if ( s->rdata_size < s->rdata_pos + len ) {
		ShowError("RFIFOSKIP: skipped past end of read buffer! Adjusting from %d to %d (session #%d)\n", len, RFIFOREST(fd), fd);
		len = RFIFOREST(fd);
	}

	s->rdata_pos = s->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif
	return 0;
}

/// advance the WFIFO cursor (marking 'len' bytes for sending)
int WFIFOSET(int fd, size_t len)
{
	size_t newreserve;
	struct socket_data* s = session[fd];

	if( !session_isValid(fd) || s->wdata == NULL )
		return 0;

	if (is_gepard_active == true)
	{
			gepard_process_packet(fd, s->wdata + s->wdata_size, len, &s->send_crypt);
	}
	// we have written len bytes to the buffer already before calling WFIFOSET
	if(s->wdata_size+len > s->max_wdata)
	{	// actually there was a buffer overflow already
		uint32 ip = s->client_addr;
		ShowFatalError("WFIFOSET: Write Buffer Overflow. Connection %d (%d.%d.%d.%d) has written %u bytes on a %u/%u bytes buffer.\n", fd, CONVIP(ip), (unsigned int)len, (unsigned int)s->wdata_size, (unsigned int)s->max_wdata);
		ShowDebug("Likely command that caused it: 0x%x\n", (*(uint16*)(s->wdata + s->wdata_size)));
		// no other chance, make a better fifo model
		exit(EXIT_FAILURE);
	}

	if( len > 0xFFFF )
	{
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowFatalError("WFIFOSET: Packet 0x%x is too big. (len=%u, max=%u)\n", (*(uint16*)(s->wdata + s->wdata_size)), (unsigned int)len, 0xFFFF);
		exit(EXIT_FAILURE);
	}
	else if( len == 0 )
	{
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET: Attempted to send zero-length packet, most likely 0x%04x (please report this).\n", WFIFOW(fd,0));
		return 0;
	}

	if( !s->flag.server ) {

		if( len > socket_max_client_packet ) {// see declaration of socket_max_client_packet for details
			ShowError("WFIFOSET: Dropped too large client packet 0x%04x (length=%u, max=%u).\n", WFIFOW(fd,0), len, socket_max_client_packet);
			return 0;
		}

		if( s->wdata_size+len > WFIFO_MAX ) {// reached maximum write fifo size
			ShowError("WFIFOSET: Maximum write buffer size for client connection %d exceeded, most likely caused by packet 0x%04x (len=%u, ip=%lu.%lu.%lu.%lu).\n", fd, WFIFOW(fd,0), len, CONVIP(s->client_addr));
			set_eof(fd);
			return 0;
		}

	}
	s->wdata_size += len;
#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif
	//If the interserver has 200% of its normal size full, flush the data.
	if( s->flag.server && s->wdata_size >= 2*FIFOSIZE_SERVERLINK )
		flush_fifo(fd);

	// always keep a WFIFO_SIZE reserve in the buffer
	// For inter-server connections, let the reserve be 1/4th of the link size.
	newreserve = s->flag.server ? FIFOSIZE_SERVERLINK / 4 : WFIFO_SIZE;

	// readjust the buffer to include the chosen reserve
	realloc_writefifo(fd, newreserve);

#ifdef SEND_SHORTLIST
	send_shortlist_add_fd(fd);
#endif

	return 0;
}

int do_sockets(int next)
{
	fd_set rfd;
	struct timeval timeout;
	int ret,i;

	// PRESEND Timers are executed before do_sendrecv and can send packets and/or set sessions to eof.
	// Send remaining data and process client-side disconnects here.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);
	}
#endif

	// can timeout until the next tick
	timeout.tv_sec  = next/1000;
	timeout.tv_usec = next%1000*1000;

	memcpy(&rfd, &readfds, sizeof(rfd));
	ret = sSelect(fd_max, &rfd, NULL, NULL, &timeout);

	if( ret == SOCKET_ERROR )
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: select() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}

	last_tick = time(NULL);

#if defined(WIN32)
	// on windows, enumerating all members of the fd_set is way faster if we access the internals
	for( i = 0; i < (int)rfd.fd_count; ++i )
	{
		int fd = sock2fd(rfd.fd_array[i]);
		if( session[fd] )
			session[fd]->func_recv(fd);
	}
#else
	// otherwise assume that the fd_set is a bit-array and enumerate it in a standard way
	for( i = 1; ret && i < fd_max; ++i )
	{
		if(sFD_ISSET(i,&rfd) && session[i])
		{
			session[i]->func_recv(i);
			--ret;
		}
	}
#endif

	// POSTSEND Send remaining data and handle eof sessions.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);

		if(session[i]->flag.eof) //func_send can't free a session, this is safe.
		{	//Finally, even if there is no data to parse, connections signalled eof should be closed, so we call parse_func [Skotlex]
			session[i]->func_parse(i); //This should close the session immediately.
		}
	}
#endif

	// parse input data on each socket
	for(i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if (session[i]->rdata_tick && DIFF_TICK(last_tick, session[i]->rdata_tick) > stall_time) {
			if( session[i]->flag.server ) {/* server is special */
				if( session[i]->flag.ping != 2 )/* only update if necessary otherwise it'd resend the ping unnecessarily */
					session[i]->flag.ping = 1;
			} else {
				ShowInfo("Session #%d timed out\n", i);
				set_eof(i);
			}
		}

		session[i]->func_parse(i);

		if(!session[i])
			continue;

		// after parse, check client's RFIFO size to know if there is an invalid packet (too big and not parsed)
		if (session[i]->rdata_size == RFIFO_SIZE && session[i]->max_rdata == RFIFO_SIZE) {
			set_eof(i);
			continue;
		}
		RFIFOFLUSH(i);
	}

#ifdef SHOW_SERVER_STATS
	if (last_tick != socket_data_last_tick)
	{
		char buf[1024];

		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., malloc_usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif
		socket_data_last_tick = last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif

	return 0;
}

//////////////////////////////
#ifndef MINICORE
//////////////////////////////
// IP rules and DDoS protection

typedef struct _connect_history {
	struct _connect_history* next;
	uint32 ip;
	uint32 tick;
	int count;
	unsigned ddos : 1;
} ConnectHistory;

typedef struct _access_control {
	uint32 ip;
	uint32 mask;
} AccessControl;

enum _aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static AccessControl* access_allow = NULL;
static AccessControl* access_deny = NULL;
static int access_order    = ACO_DENY_ALLOW;
static int access_allownum = 0;
static int access_denynum  = 0;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
/// Connection history, an array of linked lists.
/// The array's index for any ip is ip&0xFFFF
static ConnectHistory* connect_history[0x10000];

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %d.%d.%d.%d %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	ConnectHistory* hist = connect_history[ip&0xFFFF];
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for( i=0; i < access_allownum; ++i ){
		if( (ip & access_allow[i].mask) == (access_allow[i].ip & access_allow[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from allow list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_allow[i].ip),
					CONVIP(access_allow[i].mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for( i=0; i < access_denynum; ++i ){
		if( (ip & access_deny[i].mask) == (access_deny[i].ip & access_deny[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from deny list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_deny[i].ip),
					CONVIP(access_deny[i].mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
	case ACO_DENY_ALLOW:
	default:
		if( is_denyip )
			connect_ok = 0; // Reject
		else if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 1; // Accept
		break;
	case ACO_ALLOW_DENY:
		if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else if( is_denyip )
			connect_ok = 0; // Reject
		else
			connect_ok = 1; // Accept
		break;
	case ACO_MUTUAL_FAILURE:
		if( is_allowip && !is_denyip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 0; // Reject
		break;
	}

	// Inspect connection history
	while( hist ) {
		if( ip == hist->ip )
		{// IP found
			if( hist->ddos )
			{// flagged as DDoS
				return (connect_ok == 2 ? 1 : 0);
			} else if( DIFF_TICK(gettick(),hist->tick) < ddos_interval )
			{// connection within ddos_interval
				hist->tick = gettick();
				if( hist->count++ >= ddos_count )
				{// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %d.%d.%d.%d!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
			} else
			{// not within ddos_interval, clear data
				hist->tick  = gettick();
				hist->count = 0;
				return connect_ok;
			}
		}
		hist = hist->next;
	}
	// IP not found, add to history
	CREATE(hist, ConnectHistory, 1);
	memset(hist, 0, sizeof(ConnectHistory));
	hist->ip   = ip;
	hist->tick = gettick();
	hist->next = connect_history[ip&0xFFFF];
	connect_history[ip&0xFFFF] = hist;
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static TIMER_FUNC(connect_check_clear){
	int i;
	int clear = 0;
	int list  = 0;
	ConnectHistory root;
	ConnectHistory* prev_hist;
	ConnectHistory* hist;

	for( i=0; i < 0x10000 ; ++i ){
		prev_hist = &root;
		root.next = hist = connect_history[i];
		while( hist ){
			if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
					(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				prev_hist->next = hist->next;
				aFree(hist);
				hist = prev_hist->next;
				clear++;
			} else {
				prev_hist = hist;
				hist = hist->next;
			}
			list++;
		}
		connect_history[i] = root.next;
	}
	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}
	return list;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
int access_ipmask(const char* str, AccessControl* acc)
{
	uint32 ip;
	uint32 mask;

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%3u.%3u.%3u.%3u/%3u.%3u.%3u.%3u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u/%3u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%d.%d.%d.%d mask:%d.%d.%d.%d\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}
//////////////////////////////
#endif
//////////////////////////////

int socket_config_read(const char* cfgName)
{
	char line[1024],w1[1024],w2[1024];
	FILE *fp;

	fp = fopen(cfgName, "r");
	if(fp == NULL) {
		ShowError("File not found: %s\n", cfgName);
		return 1;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if(line[0] == '/' && line[1] == '/')
			continue;
		if(sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		if (!strcmpi(w1, "stall_time")) {
			stall_time = atoi(w2);
			if( stall_time < 3 )
				stall_time = 3;/* a minimum is required to refrain it from killing itself */
		}
#ifndef MINICORE
		else if (!strcmpi(w1, "enable_ip_rules")) {
			ip_rules = config_switch(w2);
		} else if (!strcmpi(w1, "order")) {
			if (!strcmpi(w2, "deny,allow"))
				access_order = ACO_DENY_ALLOW;
			else if (!strcmpi(w2, "allow,deny"))
				access_order = ACO_ALLOW_DENY;
			else if (!strcmpi(w2, "mutual-failure"))
				access_order = ACO_MUTUAL_FAILURE;
		} else if (!strcmpi(w1, "allow")) {
			RECREATE(access_allow, AccessControl, access_allownum+1);
			if (access_ipmask(w2, &access_allow[access_allownum]))
				++access_allownum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		} else if (!strcmpi(w1, "deny")) {
			RECREATE(access_deny, AccessControl, access_denynum+1);
			if (access_ipmask(w2, &access_deny[access_denynum]))
				++access_denynum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		}
		else if (!strcmpi(w1,"ddos_interval"))
			ddos_interval = atoi(w2);
		else if (!strcmpi(w1,"ddos_count"))
			ddos_count = atoi(w2);
		else if (!strcmpi(w1,"ddos_autoreset"))
			ddos_autoreset = atoi(w2);
		else if (!strcmpi(w1,"debug"))
			access_debug = config_switch(w2);
#endif
		else if (!strcmpi(w1, "import"))
			socket_config_read(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}


void socket_final(void)
{
	int i;
#ifndef MINICORE
	ConnectHistory* hist;
	ConnectHistory* next_hist;

	for( i=0; i < 0x10000; ++i ){
		hist = connect_history[i];
		while( hist ){
			next_hist = hist->next;
			aFree(hist);
			hist = next_hist;
		}
	}
	if( access_allow )
		aFree(access_allow);
	if( access_deny )
		aFree(access_deny);
#endif

	for( i = 1; i < fd_max; i++ )
		if(session[i])
			do_close(i);

	// session[0]
	aFree(session[0]->rdata);
	aFree(session[0]->wdata);
	aFree(session[0]->session_data);
	aFree(session[0]);
	session[0] = NULL;

#ifdef WIN32
	// Shut down windows networking
	if( WSACleanup() != 0 ){
		ShowError("socket_final: WinSock could not be cleaned up! %s\n", error_msg() );
	}
#endif
}

/// Closes a socket.
void do_close(int fd)
{
	if( fd <= 0 ||fd >= FD_SETSIZE )
		return;// invalid

	flush_fifo(fd); // Try to send what's left (although it might not succeed since it's a nonblocking socket)
	sFD_CLR(fd, &readfds);// this needs to be done before closing the socket
	sShutdown(fd, SHUT_RDWR); // Disallow further reads/writes
	sClose(fd); // We don't really care if these closing functions return an error, we are just shutting down and not reusing this socket.
	if (session[fd]) delete_session(fd);
}

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
int socket_getips(uint32* ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if( gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR )
		{
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		}
		else
		{
			u_long** a;
			struct hostent* hent;
			hent = gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for( ;num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if( sIoctl(fd, SIOCGIFCONF, &ic) == -1 )
		{
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			return 0;
		}
		else
		{
			int pos;
			for( pos=0; pos < ic.ifc_len && num < max; )
			{
				struct ifreq* ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in*a = (struct sockaddr_in*) &(ir->ifr_addr);
				if( a->sin_family == AF_INET ){
					ad = ntohl(a->sin_addr.s_addr);
					if( ad != INADDR_LOOPBACK && ad != INADDR_ANY )
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

void socket_init(void)
{
	const char *SOCKET_CONF_FILENAME = "conf/packet_athena.conf";
	unsigned int rlim_cur = FD_SETSIZE;

#ifdef WIN32
	{// Start up windows networking
		WSADATA wsaData;
		WORD wVersionRequested = MAKEWORD(2, 0);
		if( WSAStartup(wVersionRequested, &wsaData) != 0 )
		{
			ShowError("socket_init: WinSock not available!\n");
			return;
		}
		if( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0 )
		{
			ShowError("socket_init: WinSock version mismatch (2.0 or compatible required)!\n");
			return;
		}
	}
#elif defined(HAVE_SETRLIMIT) && !defined(CYGWIN)
	// NOTE: getrlimit and setrlimit have bogus behaviour in cygwin.
	//       "Number of fds is virtually unlimited in cygwin" (sys/param.h)
	{// set socket limit to FD_SETSIZE
		struct rlimit rlp;
		if( 0 == getrlimit(RLIMIT_NOFILE, &rlp) )
		{
			rlp.rlim_cur = FD_SETSIZE;
			if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
			{// failed, try setting the maximum too (permission to change system limits is required)
				rlp.rlim_max = FD_SETSIZE;
				if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
				{// failed
					const char *errmsg = error_msg();
					int rlim_ori;
					// set to maximum allowed
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_ori = (int)rlp.rlim_cur;
					rlp.rlim_cur = rlp.rlim_max;
					setrlimit(RLIMIT_NOFILE, &rlp);
					// report limit
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_cur = rlp.rlim_cur;
					ShowWarning("socket_init: failed to set socket limit to %d, setting to maximum allowed (original limit=%d, current limit=%d, maximum allowed=%d, %s).\n", FD_SETSIZE, rlim_ori, (int)rlp.rlim_cur, (int)rlp.rlim_max, errmsg);
				}
			}
		}
	}
#endif

	// Get initial local ips
	naddr_ = socket_getips(addr_,16);

	sFD_ZERO(&readfds);
#if defined(SEND_SHORTLIST)
	memset(send_shortlist_set, 0, sizeof(send_shortlist_set));
#endif

	socket_config_read(SOCKET_CONF_FILENAME);

	// Gepard Shield
	gepard_config_read();
	// Gepard Shield

	// initialise last send-receive tick
	last_tick = time(NULL);

	// session[0] is now currently used for disconnected sessions of the map server, and as such,
	// should hold enough buffer (it is a vacuum so to speak) as it is never flushed. [Skotlex]
	create_session(0, null_recv, null_send, null_parse); //FIXME this is causing leak

#ifndef MINICORE
	// Delete old connection history every 5 minutes
	memset(connect_history, 0, sizeof(connect_history));
	add_timer_func_list(connect_check_clear, "connect_check_clear");
	add_timer_interval(gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);
#endif

	ShowInfo("Server supports up to '" CL_WHITE "%u" CL_RESET "' concurrent connections.\n", rlim_cur);
}


bool session_isValid(int fd)
{
	return ( fd > 0 && fd < FD_SETSIZE && session[fd] != NULL );
}

bool session_isActive(int fd)
{
	return ( session_isValid(fd) && !session[fd]->flag.eof );
}

// Resolves hostname into a numeric ip.
uint32 host2ip(const char* hostname)
{
	struct hostent* h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

// Converts a numeric ip into a dot-formatted string.
// Result is placed either into a user-provided buffer or a static system buffer.
const char* ip2str(uint32 ip, char ip_str[16])
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
uint32 str2ip(const char* ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Neccessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending or eof handling.
void send_shortlist_add_fd(int fd)
{
	int i;
	int bit;

	if( !session_isValid(fd) )
		return;// out of range

	i = fd/32;
	bit = fd%32;

	if( (send_shortlist_set[i]>>bit)&1 )
		return;// already in the list

	if( send_shortlist_count >= ARRAYLENGTH(send_shortlist_array) )
	{
		ShowDebug("send_shortlist_add_fd: shortlist is full, ignoring... (fd=%d shortlist.count=%d shortlist.length=%d)\n", fd, send_shortlist_count, ARRAYLENGTH(send_shortlist_array));
		return;
	}

	// set the bit
	send_shortlist_set[i] |= 1<<bit;
	// Add to the end of the shortlist array.
	send_shortlist_array[send_shortlist_count++] = fd;
}

// Do pending network sends and eof handling from the shortlist.
void send_shortlist_do_sends()
{
	int i;

	for( i = send_shortlist_count-1; i >= 0; --i )
	{
		int fd = send_shortlist_array[i];
		int idx = fd/32;
		int bit = fd%32;

		// Remove fd from shortlist, move the last fd to the current position
		--send_shortlist_count;
		send_shortlist_array[i] = send_shortlist_array[send_shortlist_count];
		send_shortlist_array[send_shortlist_count] = 0;

		if( fd <= 0 || fd >= FD_SETSIZE )
		{
			ShowDebug("send_shortlist_do_sends: fd is out of range, corrupted memory? (fd=%d)\n", fd);
			continue;
		}
		if( ((send_shortlist_set[idx]>>bit)&1) == 0 )
		{
			ShowDebug("send_shortlist_do_sends: fd is not set, why is it in the shortlist? (fd=%d)\n", fd);
			continue;
		}
		send_shortlist_set[idx]&=~(1<<bit);// unset fd
		// If this session still exists, perform send operations on it and
		// check for the eof state.
		if( session[fd] )
		{
			// Send data
			if( session[fd]->wdata_size )
				session[fd]->func_send(fd);

			// If it's been marked as eof, call the parse func on it so that
			// the socket will be immediately closed.
			if( session[fd]->flag.eof )
				session[fd]->func_parse(fd);

			// If the session still exists, is not eof and has things left to
			// be sent from it we'll re-add it to the shortlist.
			if( session[fd] && !session[fd]->flag.eof && session[fd]->wdata_size )
				send_shortlist_add_fd(fd);
		}
	}
}
#endif

bool is_gepard_active;
uint32 gepard_rand_seed;
uint32 allowed_gepard_grf_hash;
uint32 min_allowed_gepard_version;

const unsigned char* shield_matrix = (const unsigned char*)

	"\xb6\xdc\xe1\xf8\xc4\xe8\x7e\xad\xaf\xad\xcb\x77\xc4\x87\xa4\x2c"
	"\x90\x6d\x0d\x49\xbf\x9e\xb5\xb5\xf8\x65\x3f\xc9\x42\x3c\xe6\x97"
	"\x44\xc6\x98\x86\x07\xf8\x97\x2d\x70\x64\x2c\x8b\x25\xe5\x18\x0d"
	"\x97\x4d\xb5\xf1\x56\x3b\x82\x86\x7d\x27\x7d\x4a\x47\xed\x9d\xed"
	"\x27\xdc\x41\x4b\xf7\x7b\xd7\x36\x09\xa3\xb5\xd8\x35\x1c\x47\xe3"
	"\xbd\xca\x93\xd9\x14\x36\xc7\xbf\xd1\xda\xb8\x5b\x86\xa5\x1b\xed"
	"\x1e\x83\x52\x84\x22\x5a\x23\xc3\x34\x63\x20\x5a\xa5\x3b\xa6\xf4"
	"\x55\x92\x3f\xd8\x11\xe0\xa9\x93\x01\x82\x09\xd1\xa3\x1c\x52\xd7"
	"\x8b\x33\x86\xa3\xe9\xd2\xde\xbe\xcb\xb1\xe6\x3f\x0a\x24\xad\xfa"
	"\x52\x64\x93\xfa\x4c\xe2\x52\xa6\x39\xb4\xcc\xb5\x26\x5e\xbe\xdb"
	"\x76\xf5\xda\x4f\x65\xf6\xf6\x09\xd0\x2c\xc7\x69\xdb\x8e\xd7\xa0"
	"\xcd\x98\x30\x7e\xa4\xba\xed\x15\xca\x9c\x25\xc3\xf6\xcb\xdd\xa3"
	"\x0a\x6c\x92\x60\x85\x2d\x59\xf5\xe4\x88\x46\x70\xf6\x85\xa3\x09"
	"\x06\x95\x7b\xd7\x62\x35\x2c\x6b\x2d\xf7\xf4\x6d\xe3\x9b\xb1\xc9"
	"\x15\x48\xb2\xe4\x42\xae\xf8\x4e\x53\x8f\xab\x9d\x9c\xe7\x96\x48"
	"\x59\xd9\x1c\x2f\xad\xf8\xc2\xab\xf9\x19\x68\x55\xa1\xd4\xbd\xdc"
	"\x0b\xd1\x86\x1d\x77\x89\xcc\x4d\x06\x9b\x80\xee\x6f\xe7\x38\xe6"
	"\xcd\xf6\x7e\x5f\x93\x7b\x69\x4c\x6e\x65\xea\x55\xc4\x54\x8e\xdf"
	"\x01\xe2\x1c\x7f\x62\x9e\x4e\xa2\x0d\x9e\x94\x18\x78\x8b\x92\x63"
	"\x0c\x11\x53\xf6\x84\x89\xdd\xb7\x6d\xd8\x2e\xf9\x48\xcb\xaf\x49"
	"\x33\xec\x45\x36\x28\x25\xfc\xf2\x1d\x9d\xfb\x22\xa5\xae\x37\xad"
	"\xe2\x63\x8d\x3b\x58\xc1\xe0\x4b\xfb\x80\x27\x82\x0a\x3e\x34\x85"
	"\x81\x71\x17\x1d\x50\x26\x5c\xd6\x0e\xae\x8c\xbf\x45\x22\xb7\xaa"
	"\x40\xb8\x66\xa1\x47\x1a\xb5\x5a\x45\x7e\x0f\xe5\x4d\x07\xb0\x72"
	"\x6c\x09\xec\xc6\x45\xfe\x70\xd8\xd9\x7e\xe2\xa6\x8d\x82\x2e\xb4"
	"\xbb\x74\x59\x58\xee\x58\x25\xa8\x15\x09\xe2\xc9\xb7\xd0\x3e\x63"
	"\x1d\xdd\xe5\xf9\x57\x61\x47\x7b\x22\x4f\x5d\x38\x15\x8c\xb4\x97"
	"\x8b\x0b\x27\xbc\xd0\x19\xfc\x71\xde\x6c\x64\x0d\x54\x1d\xfc\x20"
	"\xdc\x30\xe1\x2d\x3a\x54\x6d\x2f\xaa\x74\x9e\x29\xd9\x48\x6b\x14"
	"\x8f\x05\x54\x63\x51\x4c\x8d\x64\x39\x04\x97\xbe\x11\x41\x0d\xe2"
	"\x1c\x52\x09\x10\x03\xb0\x75\xde\xdb\xd4\x0f\xe4\xbb\xb6\x75\x60"
	"\xc5\x81\x28\x13\xba\xb5\x2b\x20\x5b\xc3\xc7\xa3\x41\x65\x13\x5a"
	"\x6c\xac\xc4\x83\xaf\xa4\x76\x66\x40\x6d\xd8\x89\xfe\x28\xfa\xa4"
	"\x55\x30\xae\xc7\x3a\x6c\x2f\x3d\x26\x32\x7f\x35\x99\x85\x3a\xaa"
	"\x84\xb9\xc2\x1e\x9e\xb1\x0c\x93\x09\xcf\x6b\x6a\x4b\x44\xa7\xfd"
	"\x86\xd6\xb8\xb1\xe1\x5d\xf5\xc5\x19\x69\x11\x9f\x35\x73\x30\x6a"
	"\xc0\x88\x75\xa8\x93\xad\x53\xac\x88\x1e\x7a\x8d\x2e\x05\x2a\x7e"
	"\xc5\xce\xd9\xb3\xa5\x47\x5f\xb5\x5c\x17\x92\x42\x14\x55\xa5\xa3"
	"\x1f\x3d\x13\x9f\xb5\xc2\xef\xe9\xb8\x13\x7c\x2e\x18\xbb\xb7\xa9"
	"\x24\x06\x6a\x64\x60\x3e\xcf\x80\x38\xfc\x5b\x33\x16\xa1\xcf\x56"
	"\xc2\x8d\x16\x36\x10\xed\x08\xf4\x34\x78\xab\xb9\xdc\x88\x86\x79"
	"\xd6\xfb\x07\x91\x4e\xaa\xb1\x8d\x9a\x72\x0a\x3a\x04\xa4\x6b\xf5"
	"\x72\x47\x3c\x50\x92\x01\xc6\x6f\x3b\xb0\x09\xd2\x36\x64\xd3\xd9"
	"\x36\x48\x10\xb8\x12\x46\xf0\xb3\x16\xe1\x22\x53\x86\x02\xb1\xe8"
	"\x19\xc7\x08\x88\x10\xa2\xd9\x6d\x31\xae\x57\x50\x3e\x17\x5e\xad"
	"\x3f\x12\x28\x8d\x2f\x24\x7d\x43\xe0\x49\xdf\xb0\x2c\xab\x68\x8a"
	"\x45\x82\xbe\x2d\x40\xcc\xf4\x77\x9d\xfb\x1d\xbd\x76\xc2\x69\x48"
	"\x93\x97\x39\x79\x91\x25\xcc\x7d\xd3\xba\x95\xb5\x68\x6c\xd2\xa8"
	"\xaa\x7f\xeb\xbe\xbf\x4c\xce\x88\x2e\xb3\xa5\xd7\x43\x58\x3d\x74"
	"\x77\xa9\xed\x95\x85\x82\xd6\x19\xed\xdb\x4d\xf9\x90\xdf\x3a\x87"
	"\xa0\xd8\x5d\x72\x0c\x42\xa0\x90\xb1\x06\x22\x13\xed\x1e\x25\x6c"
	"\xd4\x2f\x36\xb2\xbb\x48\x98\xbf\xcf\x69\x78\x4c\xdf\xf7\xed\x5f"
	"\x9f\xbf\x24\xb1\x0a\xa5\x2b\xf3\x1d\xb7\x80\x93\x21\x31\xf0\xe3"
	"\xb6\x1f\x49\xd3\x4a\x55\x13\x8e\xc0\xae\x4b\xaa\x74\x78\x3f\xd8"
	"\xc9\x75\x96\x1b\x7f\xc1\x2f\x0b\x86\x21\x3d\xb5\x6f\xfd\xf3\x7f"
	"\x4f\x09\x1c\xb1\x2a\x5d\x4b\x98\xa9\x8f\xbf\x4c\x50\xf9\x03\x14"
	"\xde\xd1\xd0\x22\x99\x30\x74\xa1\xaa\xae\x11\x08\xca\x47\x86\xd6"
	"\xf3\x8c\x6b\x36\x39\x68\x48\xe3\x99\x01\x92\x17\x5a\xea\x93\x23"
	"\x47\x41\x2e\x64\xe5\xe6\xc4\x78\xe8\xe0\x1b\xcb\x8d\xa5\x84\xf7"
	"\x1d\x5e\x38\x82\xb8\x53\x97\xe9\xc0\x8f\xc5\xa9\x5c\x89\xcd\x0f"
	"\x0f\x42\xd3\x84\xd9\xa9\x6f\x41\x47\x4a\x40\x78\xf2\x03\xcc\xe4"
	"\xe5\x4a\xc6\xe8\xcd\xcb\xca\x98\x75\x57\x9c\x53\x85\xec\x94\xcf"
	"\x63\x68\x24\x4b\xcb\x12\xc7\xa6\x6a\x15\xa4\x38\x1c\x9d\x42\x10"
	"\x12\x2b\x1e\x71\x83\x57\xf4\x53\xb3\x8b\xa2\x19\x67\x7b\xcb\x58"
	"\x17\x59\x4d\xdb\xf5\x8e\x23\x44\xa1\x7c\x37\x6a\x8d\x09\xcd\x64"
	"\x05\xf4\x8b\xd6\x44\xcd\x30\xee\x96\xf2\x24\xb3\xf9\xf4\xde\x88"
	"\x23\x52\x3b\x0a\xf9\xe0\x5c\x28\xd9\xd1\x24\xa0\x2f\xab\xdb\xbe"
	"\x47\xa9\x1e\x0a\x63\x59\x97\x35\xe1\x67\xb1\x0f\x95\x67\x3b\xb8"
	"\x20\x22\x9f\xe1\x5a\x9e\x52\x58\x29\xf8\xde\x21\xcd\x40\xda\x70"
	"\x86\xe4\xaa\x2d\x96\xfa\x4d\x65\xf9\xd6\xa0\xcc\xfa\x39\x51\xb3"
	"\x4e\xab\xf2\x1f\xfd\x31\xe8\xcc\x45\x69\x20\xe7\x19\x55\xbd\x3d"
	"\x14\x52\x49\x98\xf5\x86\xf5\x30\x6a\xc3\x8a\x3f\xc9\xa2\x17\x39"
	"\x10\xe5\x6c\x34\xb0\xd7\x85\xef\x8c\xb0\x62\x21\xa5\xcd\xfd\xde"
	"\xe3\xb4\x56\x58\x80\xa3\xb8\x3c\x60\x44\x4c\xf0\x8a\x31\x88\x7b"
	"\x6c\xdd\x0c\x46\x22\x22\x91\xa3\xfd\xed\xe3\xb2\x6c\xe1\x16\x02"
	"\x8f\x60\xf1\xaa\x15\x4e\xc3\xa4\x2e\x03\x86\x9d\x26\xc4\x1f\x21"
	"\x0e\xb0\x14\x2e\x65\x77\x7e\xba\xbc\xd5\x28\x30\xc9\x9a\x85\x49"
	"\x53\x3f\x7f\x83\x7c\xd4\x46\x74\x48\x3e\x1f\xb6\xec\x91\xe0\x45"
	"\x44\x92\x8a\xf9\x72\x91\x3d\xfd\x91\x31\xf7\x65\x7d\x56\x51\xc7"
	"\x11\x4e\xa7\x8b\xdd\x5c\x76\xb1\x4a\x48\xbf\xdf\x10\xa1\x50\x78"
	"\x81\xca\xb8\xeb\xa3\x7d\xc3\x29\xe7\xda\x5b\x50\x2d\xc9\xfe\x87"
	"\x4c\x1f\xd6\x9b\x47\xdc\x8b\xce\xf0\x86\x54\x71\xa5\xd1\xf7\x3c"
	"\xdd\x35\xac\x78\xb8\x1d\x8e\xeb\x4f\x44\x25\xa3\xdf\xf9\x9c\x84"
	"\xae\xd6\x3d\x47\xa8\xa1\x43\xb7\x9e\x75\x0f\xf8\xa7\xd1\xe5\x88"
	"\x92\xbf\xb9\x49\x56\x26\x1c\xe9\x7c\x72\xe5\xc6\x02\xc3\xb7\x31"
	"\x05\x2e\x4f\xcd\xd9\xca\xdd\x4a\x59\xa0\xe3\x36\x76\xa7\x2c\xc6"
	"\xfe\x6e\xf5\xbc\x81\x23\x6d\x3d\x47\x7c\x75\xd2\xe5\xd3\x65\xf2"
	"\x41\x72\x43\xa9\x13\xcb\x20\xd8\xca\xab\x0d\x1d\x53\xaa\xde\x57"
	"\x27\xd9\x3a\xe3\x28\x71\x8a\x6f\xaa\x8d\xee\x17\x3d\xad\xbc\x21"
	"\x76\x85\x97\x85\xf1\xeb\xd2\xa7\xc0\x4c\x07\x57\x65\x88\x99\x8e"
	"\x30\xab\x26\x83\x17\x43\x7e\x03\xc7\xe8\x32\x96\xa2\xa7\xd8\x08"
	"\x5f\xdc\x8b\xc0\x78\xc7\x42\x72\x2e\x4e\x13\x41\xb5\xc1\xf7\x30"
	"\xe6\x22\x1b\x17\x84\x1e\x55\xe8\x62\x61\xe0\x07\x91\xed\x5a\xeb"
	"\xd7\x81\xa2\x6e\x8a\xce\xbf\x67\xa7\x0e\xb6\x6a\xb2\x2c\x9d\x79"
	"\x39\x13\x3f\x4a\x86\x5a\x25\x0c\x61\xdd\xe3\xd2\xe9\xfd\xe4\xfe"
	"\xdf\x10\xa6\xd6\xf1\x45\x9e\x27\xe6\xfe\x3b\x98\xaf\x6f\x2e\x19"
	"\x39\xe3\x7c\xfe\x17\xa7\x82\x47\xd1\x5c\x65\x99\x71\xaa\x9f\xeb"
	"\x1e\x3b\xa1\xf5\xdc\x41\xb8\xc8\xcb\x27\xad\xc3\xe2\x87\x55\x32"
	"\x9f\x11\x02\x4b\x18\x07\x09\xe9\x62\xec\x54\x2c\x4f\x9b\x36\x4f"
	"\xda\xc6\xe5\x7a\xdc\x31\xe9\xd6\xd6\x21\x5e\x98\x67\xc7\xbf\xdb"
	"\xc5\x29\x41\x78\xcb\x4e\x56\x39\x68\xb2\x65\x93\x90\x4b\x58\x39"
	"\x03\x8b\x85\x47\xe5\xd2\x14\x4d\xac\x1b\xe3\x78\xb9\xd2\x1f\x20"
	"\xab\xcf\x70\x83\xd9\x27\x0e\x6d\xd9\x68\x8d\x87\xa5\x87\x3a\x30"
	"\x27\xf8\x5a\xf4\x53\xba\x1b\xa0\x99\xd5\x95\xf4\x3e\xa1\x29\x7f"
	"\x73\xbc\x09\x9e\xcc\x10\xd5\xb0\xd4\x57\x88\x78\xe2\xf4\x12\xab"
	"\x7c\x10\x22\x4f\x60\xd0\xe6\xb4\x0b\xa9\x92\xd9\xb9\x02\x17\xea"
	"\x64\xb9\x4b\x2f\x15\xd9\x59\xa4\x98\xe1\x56\x08\x22\x88\x1d\x1b"
	"\xdb\xe3\xd5\x55\xb0\xcf\xe5\x65\x90\x7f\x3a\x23\xd7\x93\x27\xcc"
	"\x69\x27\xb6\xce\x85\x2b\x46\xdc\x08\x7b\x3a\x8d\x1a\x8d\x1b\xdb"
	"\xc1\x9f\x01\xb9\x48\x49\x86\x22\x63\xd6\x33\xfe\xa6\x4c\x9a\x7c"
	"\x11\x78\x93\xcb\xd6\xfc\x50\xe1\x2c\x2d\x3a\x12\xb2\xa3\x4e\x46"
	"\xcf\x22\x69\xe4\x10\x9f\xbe\xc5\x5b\xc1\x66\x54\x98\xf3\xb7\x4b"
	"\x8e\x34\xea\x25\xa2\x1d\x2e\x2f\x30\x92\xa2\xd5\xab\xbb\x7f\xa2"
	"\x4a\xd6\x3b\xf2\xd6\x8a\x08\x6e\x77\xe4\x22\x3b\x03\xa7\xc6\x7b"
	"\xb9\xf6\x8a\x92\x68\xae\x19\x34\x64\xda\x02\x4b\x4e\x9f\x79\x2d"
	"\x9b\x87\x66\xb2\xcd\x17\x5d\xa1\x58\xfc\xf1\x22\xa1\xd8\x97\xc3"
	"\x0b\xed\x06\xfd\x0d\xa5\x51\xd5\x3c\x4c\xab\x17\xc8\xe6\x8c\x17"
	"\x4e\x8e\x1f\x28\x89\x23\x40\x22\x45\x56\xf0\x23\x92\xca\x7a\xd0"
	"\x23\xde\xb2\x82\x56\xcc\x18\x6c\xcf\x3e\xb6\x95\x29\x82\x8b\x05"
	"\x94\x76\xdd\x8a\x04\x64\x35\x99\x28\xd3\xf6\x58\x58\x18\xc4\xbf"
	"\xc5\x1f\x2a\x74\x71\xc1\xb5\xc2\x5b\x1d\x7e\x55\x65\x34\xcf\x91"
	"\xc3\x61\xde\xc4\x9a\x61\x45\x75\x0d\x6b\xbf\x09\xd8\x2c\xd0\xa3"
	"\x57\x9a\xcb\x58\xeb\x76\xf2\x9a\x3f\xe9\xa0\x17\xd4\x12\xb3\x48"
	"\x53\x05\xa1\x76\x8e\x76\x7c\x0d\x27\x29\xcd\x52\xde\x48\xfb\x85"
	"\x65\xd0\xb8\xe5\xba\xaf\x9f\x26\xfd\xb6\x83\xd2\xb4\x89\x17\xaa"
	"\x62\xaa\xe9\x74\x05\xd3\xeb\xce\x4d\xa8\xe4\x04\x19\x01\x28\x5e"
	"\x1d\xd3\xd7\x0d\x34\x89\x0e\x8e\x40\xad\xca\x34\xa5\xd6\xdc\x2e"
	"\x30\x2e\xc0\x45\x09\x7c\xa7\x1d\xf6\x1e\x10\x23\x19\xbf\x3a\x9d";

void gepard_config_read()
{
	const char* conf_name = "conf/gepard_shield.conf";
	char line[1024], w1[1024], w2[1024];

	FILE* fp = fopen(conf_name, "r");

	is_gepard_active = false;

	if (fp == NULL)
	{
		ShowError("Gepard configuration file (%s) not found. Shield disabled.\n", conf_name);
		return;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if (!strcmpi(w1, "gepard_shield_enabled"))
		{
			is_gepard_active = (bool)config_switch(w2);
		}
	}

	fclose(fp);

	conf_name = "conf/gepard_version.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		min_allowed_gepard_version = 0;
		ShowError("Gepard version file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &min_allowed_gepard_version);

	fclose(fp);

	conf_name = "conf/gepard_grf_hash.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		allowed_gepard_grf_hash = 0;
		ShowError("Gepard GRF hash file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &allowed_gepard_grf_hash);

	fclose(fp);
}

bool gepard_process_packet(int fd, uint8* packet_data, uint32 packet_size, struct gepard_crypt_link* link)
{
	uint16 packet_id = RBUFW(packet_data, 0);

	switch (packet_id)
	{
		case CS_GEPARD_SYNC:
		{
			uint32 control_value;

			if (RFIFOREST(fd) < 6)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, 4, &session[fd]->sync_crypt);

			control_value = RFIFOL(fd, 2);

			if (control_value == 0xDDCCBBAA)
			{
				session[fd]->gepard_info.sync_tick = gettick();
			}

			RFIFOSKIP(fd, 6);

			return true;
		}
		break;

		case CS_LOGIN_PACKET_1:
		case CS_LOGIN_PACKET_2:
		case CS_LOGIN_PACKET_3:
		case CS_LOGIN_PACKET_4:
		case CS_LOGIN_PACKET_5:
		{
			set_eof(fd);
			return true;
		}
		break;

		case CS_LOGIN_PACKET:
		{
			if (RFIFOREST(fd) < 55)
			{
				return false;
			}

			if (session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, RFIFOREST(fd) - 2, link);
		}
		break;

		case CS_LOGIN_PACKET_6:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			if (session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, RFIFOREST(fd) - 4, link);
		}
		break;

		case CS_WHISPER_TO:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_WALK_TO_XY:
		case CS_USE_SKILL_TO_ID:
		case CS_USE_SKILL_TO_POS:
		{
			if (packet_size < 2 || RFIFOREST(fd) < packet_size)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, packet_size - 2, link);
		}
		break;

		case SC_WHISPER_FROM:
		case SC_SET_UNIT_IDLE:
		case SC_SET_UNIT_WALKING:
		{
			if (&session[fd]->send_crypt != link)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_GEPARD_INIT_ACK:
		{
			uint32 grf_hash_number;
			uint32 unique_id, unique_id_, shield_ver;

			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RFIFOW(fd, 2)))
			{
				return true;
			}

			if (packet_size < 24)
			{
				ShowWarning("gepard_process_packet: invalid size of CS_GEPARD_INIT_ACK packet: %u\n", packet_size);
				set_eof(fd);
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);

			unique_id  = RFIFOL(fd, 4);
			shield_ver = RFIFOL(fd, 8);
			unique_id_ = RFIFOL(fd, 12) ^ UNIQUE_ID_XOR;
			grf_hash_number = RFIFOL(fd, 20);

			RFIFOSKIP(fd, packet_size);

			if (!unique_id || !unique_id_ || unique_id != unique_id_)
			{
				WFIFOHEAD(fd, 6);
				WFIFOW(fd, 0) = SC_GEPARD_INFO;
				WFIFOL(fd, 2) = 3;
				WFIFOSET(fd, 6);
				set_eof(fd);
			}

			session[fd]->gepard_info.is_init_ack_received = true;
			session[fd]->gepard_info.unique_id = unique_id;
			session[fd]->gepard_info.gepard_shield_version = shield_ver;
			session[fd]->gepard_info.grf_hash_number = grf_hash_number;

			return true;
		}
		break;
	}

	return false;
}

inline void gepard_srand(unsigned int seed)
{
	gepard_rand_seed = seed;
}

inline unsigned int gepard_rand()
{
	return (((gepard_rand_seed = gepard_rand_seed * 214013L + 2531011L) >> 16) & 0x7fff);
}

void gepard_session_init(int fd, unsigned int recv_key, unsigned int send_key, unsigned int sync_key)
{
	uint32 i;
	uint8 random_1 = RAND_1_START;
	uint8 random_2 = RAND_2_START;

	session[fd]->recv_crypt.pos_1 = session[fd]->send_crypt.pos_1 = session[fd]->sync_crypt.pos_1 = POS_1_START;
	session[fd]->recv_crypt.pos_2 = session[fd]->send_crypt.pos_2 = session[fd]->sync_crypt.pos_2 = POS_2_START;
	session[fd]->recv_crypt.pos_3 = session[fd]->send_crypt.pos_3 = session[fd]->sync_crypt.pos_3 = 0;

	gepard_srand(recv_key ^ SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (8 * random_2) + 5;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (6 * random_1) - 2;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->recv_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;
	gepard_srand(send_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (7 * random_2) - 2;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (2 * random_1) + 9;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->send_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;
	gepard_srand(sync_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (4 * random_2) - 9;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (3 * random_1) - 5;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->sync_crypt.key[i] = random_1;
	}
}

void gepard_init(int fd, uint16 server_type)
{
	const uint16 init_packet_size = 20;
	uint16 recv_key = (gepard_rand() % 0xFFFF);
	uint16 send_key = (gepard_rand() % 0xFFFF);
	uint16 sync_key = (gepard_rand() % 0xFFFF);

	gepard_srand((unsigned)time(NULL) ^ clock());

	WFIFOHEAD(fd, init_packet_size);
	WFIFOW(fd, 0) = SC_GEPARD_INIT;
	WFIFOW(fd, 2) = init_packet_size;
	WFIFOW(fd, 4) = recv_key;
	WFIFOW(fd, 6) = send_key;
	WFIFOW(fd, 8) = server_type;
	WFIFOL(fd, 10) = GEPARD_ID;
	WFIFOL(fd, 14) = min_allowed_gepard_version;
	WFIFOW(fd, 18) = sync_key;
	WFIFOSET(fd, init_packet_size);

	gepard_session_init(fd, recv_key, send_key, sync_key);
}

void gepard_enc_dec(uint8* in_data, uint8* out_data, uint32 data_size, struct gepard_crypt_link* link)
{
	uint32 i;

	for(i = 0; i < data_size; ++i)
	{
		link->pos_1 += link->key[link->pos_3 % (KEY_SIZE-1)];
		link->pos_2 -= (80 - link->pos_1) * 7;
		link->key[link->pos_2 % (KEY_SIZE-1)] ^= link->pos_1;
		link->pos_1 += (link->pos_2 + link->pos_3) / 4;
		link->key[link->pos_3 % (KEY_SIZE-1)] ^= link->pos_1;
		out_data[i] = in_data[i] ^ link->pos_1;
		link->pos_1 *= 3;
		link->pos_2 -= data_size % 0xFF;
		link->pos_3++;
	}
}

void gepard_send_info(int fd, unsigned short info_type, const char* message)
{
	int message_len = strlen(message) + 1;
	int packet_len = 2 + 2 + 2 + message_len;

	WFIFOHEAD(fd, packet_len);
	WFIFOW(fd, 0) = SC_GEPARD_INFO;
	WFIFOW(fd, 2) = packet_len;
	WFIFOW(fd, 4) = info_type;
	safestrncpy((char*)WFIFOP(fd, 6), message, message_len);
	WFIFOSET(fd, packet_len);
}
