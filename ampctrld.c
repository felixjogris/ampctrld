#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/select.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <sys/uio.h>

#ifdef USE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#define AMPCTRLD_VERSION "1"

#define DEFAULT_ADDRESS  "0.0.0.0"
#define DEFAULT_PORT     "8082"
#define AMP_HOST         "onkyo"
#define AMP_PORT         "60128"
#define MAX_CONNS        FD_SETSIZE
#define QUEUE_LEN        8

#define log_error(fmt, params ...) do { \
  if (log_to_syslog) \
    syslog(LOG_ERR, "%s (%s:%i): " fmt "\n", \
           __FUNCTION__, __FILE__, __LINE__, ## params); \
  else \
    warnx("%s (%s:%i): " fmt, \
          __FUNCTION__, __FILE__, __LINE__, ## params); \
} while (0)

#define log_warn(fmt, params ...) do { \
  if (log_to_syslog) \
    syslog(LOG_WARNING, "%s (%s:%i): " fmt "\n", \
           __FUNCTION__, __FILE__, __LINE__, ## params); \
  else \
    warnx("%s (%s:%i): " fmt, \
          __FUNCTION__, __FILE__, __LINE__, ## params); \
} while (0)

#define log_info(fmt, params ...) do { \
  if (log_to_syslog) syslog(LOG_INFO, fmt "\n", ## params); \
  else printf(fmt "\n", ## params); \
} while (0)

/* integer to string by preprocessor */
#define XSTR(a) #a
#define STR(a) XSTR(a)

/* for accept() */
union address {
  struct sockaddr saddr;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
};

/* defines a socket */
enum conntype {
  FREE,
  LISTEN,
  AMP,
  CLIENT
};
struct sockets {
  int num_conns;
  struct {
    enum conntype type;
    char clientname[INET6_ADDRSTRLEN + 8];
  } conns[MAX_CONNS];
};

struct queue {
  int start, end;
  char entries[QUEUE_LEN][10];
};

struct amplifier {
  char *host;
  char *port;
  int socket;
  int power;
  int mute;
  int volume;
  char *input;
  struct queue queue;
};

/* used by main() and quitterm_handler() */
static int running = 1;
/* used by main() and log_*() macros */
static int log_to_syslog = 0;

int write_all (int socket, void *buf, size_t len)
{       
  size_t written_bytes;
  ssize_t res;
  
  for (written_bytes = 0; written_bytes < len; written_bytes += res) {
    res = write(socket, buf + written_bytes, len - written_bytes);
    if (res <= 0)
      return -1;
  } 
    
  return 0;
}   
    
void quitterm_handler (int sig)
{ 
  if (sig == SIGTERM)  
    log_info("SIGTERM received, going down...");
    
  running = 0;
}

void setup_signal (int sig, void (*handler)(int))
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  if (sigaction(sig, &sa, NULL) != 0)
    err(1, "signal()");
}

void setup_signals ()
{
  sigset_t sigset;

  if (sigfillset(&sigset) != 0)
    err(1, "sigfillset()");

  if (sigdelset(&sigset, SIGTERM) != 0)
    err(1, "sigdelset(SIGTERM)");

  if (sigdelset(&sigset, SIGQUIT) != 0)
    err(1, "sigdelset(SIGQUIT)");

  setup_signal(SIGTERM, quitterm_handler);
  setup_signal(SIGQUIT, quitterm_handler);
}

const struct passwd *get_user (const char *username)
{
  const struct passwd *pw = getpwnam(username);

  if (!pw)
    errx(1, "no such user: %s", username);

  return pw;
}

char const *create_client_socket_inet (const char *addr, const char *port,
                                       int *client_socket)
{
  int yes = 1, res;
  struct addrinfo hints, *result, *walk;
  char *err = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((res = getaddrinfo(addr, port, &hints, &result)) != 0)
    return gai_strerror(res);

  for (walk = result; walk; walk = walk->ai_next) {
    if ((*client_socket = socket(walk->ai_family, walk->ai_socktype, 0)) < 0)
      continue;

    if (setsockopt(*client_socket, SOL_SOCKET, SO_KEEPALIVE, &yes,
                   sizeof(yes)) ||
        connect(*client_socket, walk->ai_addr, walk->ai_addrlen))
      close(*client_socket);
    else
      break;
  }

  if (!walk)
    err = strerror(errno);

  freeaddrinfo(result);

  return err;
}

int create_listen_socket_inet (const char *ip, const char *port)
{
  int listen_socket = -1, yes = 1, res;
  struct addrinfo hints, *result, *walk;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE | AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((res = getaddrinfo(ip, port, &hints, &result)) != 0)
    errx(1, "getaddrinfo(): %s", gai_strerror(res));

  for (walk = result; walk; walk = walk->ai_next) {
    if (listen_socket >= 0)
      close(listen_socket);

    listen_socket = socket(walk->ai_family, walk->ai_socktype, 0);
    if (listen_socket < 0)
      continue;

    if (!setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT, &yes,
                    sizeof(yes)) &&
        !setsockopt(listen_socket, SOL_SOCKET, SO_KEEPALIVE, &yes,
                    sizeof(yes)) &&
        !bind(listen_socket, walk->ai_addr, walk->ai_addrlen) &&
        !listen(listen_socket, 0))
      break;
  }

  if (walk == NULL)
    err(1, "bind()");

  freeaddrinfo(result);

  return listen_socket;
}

void daemonize ()
{
  pid_t pid;

  if ((pid = fork()) < 0)
    err(1, "fork()");

  if (pid > 0)
    exit(0);

  if (setsid() == -1)
    err(1, "setsid()");

  if (chdir("/"))
    err(1, "chdir(/)");
}

void save_pidfile (const char *pidfile)
{
  int fd, len;
  char pid[16];

  fd = open(pidfile, O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_NOFOLLOW,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0)
    err(1, "cannot create %s for writing (if ampctrld is not running, "
           "please remove stale pidfile)", pidfile);

  len = snprintf(pid, sizeof(pid), "%u\n", getpid());

  if (write_all(fd, pid, len))
    errx(1, "cannot write %s", pidfile);

  if (close(fd))
    errx(1, "cannot close %s", pidfile);
}

void change_user (const struct passwd *pw)
{
  if (initgroups(pw->pw_name, pw->pw_gid))
    err(1, "initgroups()");
  if (setgid(pw->pw_gid))
    err(1, "setgid()");
  if (setuid(pw->pw_uid))
    err(1, "setuid()");
}

void client_address (struct sockets *sockets, int fd, union address uaddr)
{
  char addr[INET6_ADDRSTRLEN];
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  switch (uaddr.sin.sin_family) {
    case AF_INET:
      sin = &uaddr.sin;
      snprintf(sockets->conns[fd].clientname,
               sizeof(sockets->conns[fd].clientname), "%s:%u",
               inet_ntop(sin->sin_family, &sin->sin_addr, addr, sizeof(addr)),
               htons(sin->sin_port));
      break;
    case AF_INET6:
      sin6 = &uaddr.sin6;
      snprintf(sockets->conns[fd].clientname,
               sizeof(sockets->conns[fd].clientname), "[%s]:%u",
               inet_ntop(sin6->sin6_family, &sin6->sin6_addr, addr,
                         sizeof(addr)),
               htons(sin6->sin6_port));
      break;
    default:
      snprintf(sockets->conns[fd].clientname,
               sizeof(sockets->conns[fd].clientname),
               "<unknown address family %u>", uaddr.sin.sin_family);
      break;
  }
}

const char *parse_address (char *ip46_port, char **addr, char **port,
                           char *default_port)
{
  char *closing_bracket;

  if (*ip46_port == '[') {
    *addr = ip46_port + 1;
    closing_bracket = strchr(ip46_port, ']');
    if (!closing_bracket)
      return "missing ']' in address";

    if (*(closing_bracket + 1) && (*(closing_bracket + 1) != ':'))
      return "expected ':' after ']'";

    *closing_bracket++ = '\0';
  } else {
    *addr = ip46_port;
    closing_bracket = strchr(ip46_port, ':');
  }

  if (!closing_bracket || !*closing_bracket)
    *port  = default_port;
  else {
    *port = closing_bracket + 1;
    *closing_bracket = '\0';
  }

  return NULL;
}

void sockets_init (struct sockets *sockets)
{
  int i;

  sockets->num_conns = 0;
  for (i = 0; i < MAX_CONNS; i++)
    sockets->conns[i].type = FREE;
}

const char *sockets_add (struct sockets *sockets, int fd, enum conntype type)
{
  if (fd >= MAX_CONNS)
    return "socket descriptor too big, maximum is " STR(MAX_CONNS);

  sockets->conns[fd].type = type;
  if (fd >= sockets->num_conns)
    sockets->num_conns = fd + 1;

  return NULL;
}

void sockets_close (struct sockets *sockets, int fd)
{
  if (fd >= MAX_CONNS)
    return;

  if (sockets->conns[fd].type == FREE)
    return;

  close(fd);
  sockets->conns[fd].type = FREE;

  while ((fd >= 0) &&
         (fd + 1 == sockets->num_conns) &&
         (sockets->conns[fd].type == FREE)) {
    fd--;
    sockets->num_conns--;
  }
}

void queue_init (struct queue *queue)
{
  queue->start = queue->end = 0;
}

int queue_empty (struct queue *queue)
{
  return (queue->start == queue->end);
}

int queue_push (struct queue *queue)
{
  int ret = queue->end;

  if (++queue->end >= QUEUE_LEN)
    queue->end = 0;

  if (queue->end == queue->start)
    log_warn("%s", "queue overflow");

  return ret;
}

int queue_shift (struct queue *queue)
{
  int ret = (queue_empty(queue) ? -1 : queue->start);

  if (++queue->start >= QUEUE_LEN)
    queue->start = 0;

  return ret;
}

void amplifier_init (struct amplifier *amplifier)
{
  amplifier->host = AMP_HOST;
  amplifier->port = AMP_PORT;
  amplifier->socket = -1;
  amplifier->power = 0;
  amplifier->mute = 1;
  amplifier->volume = -6;
  amplifier->input = "ab";
}

void amplifier_disconnect (struct amplifier *amplifier)
{
  if (amplifier->socket >= 0)
    close(amplifier->socket);

  amplifier->socket = -1;
}

const char *amplifier_connect (struct amplifier *amplifier,
                               struct sockets *sockets)
{
  const char *err;

  err = create_client_socket_inet(amplifier->host, amplifier->port,
                                  &amplifier->socket);
  if (err)
    return err;

  err = sockets_add(sockets, amplifier->socket, AMP);
  if (err) {
    amplifier_disconnect(amplifier);
    return err;
  }

  queue_init(&amplifier->queue);

  return NULL;
}

int send_http (struct sockets *sockets, int fd, const char *url, int code,
               int connection_close, char *content_type, void *content,
               size_t content_len)
{
  char header[512], *reason;
  int hdr_len, len, res;
  struct iovec iov[2];

  log_info("%s \"%s\" %i", sockets->conns[fd].clientname, url, code);

  switch (code) {
    case 200:
      reason = "OK";
      break;
    case 400:
      reason = "Bad Request";
      break;
    case 404:
      reason = "Not Found";
      break;
    default:
      reason = "Internal Server Error";
      code = 500;
      break;
  }

  snprintf(header, sizeof(header), "HTTP/1.1 %i %s\r\n"
           "Server: ampctrld/version " AMPCTRLD_VERSION "\r\n"
           "Content-Type: %s\r\n"
           "Content-Length: %lu\r\n"
           "%s"
           "\r\n%n",
           code, reason, content_type, content_len,
           (connection_close ? "Connection: close\r\n" : ""),
           &hdr_len);

  iov[0].iov_base = header;
  iov[0].iov_len = hdr_len;

  iov[1].iov_base = content;
  iov[1].iov_len = content_len;

  len = hdr_len + content_len;

  res = writev(fd, iov, 2);
  if ((res < 0) || (res != len))
    return -1;

  if (connection_close)
    sockets_close(sockets, fd);

  return 0;
}

const char *bool2json (int b)
{
  return (b ? "true" : "false");
}

int send_status (struct sockets *sockets, int fd, const char *url,
                 int connection_close, struct amplifier *amplifier)
{
  char status[128];
  int cl;

  snprintf(status, sizeof(status), "{"
           "\"connected\": %s, "
           "\"power\": %s, "
           "\"mute\": %s, "
           "\"volume\": %i, "
           "\"input\": \"%s\"}\n%n",
           bool2json(amplifier->socket >= 0),
           bool2json(amplifier->power),
           bool2json(amplifier->mute),
           amplifier->volume,
           amplifier->input,
           &cl);

  return send_http(sockets, fd, url, 200, connection_close,
                   "application/json", status, cl);
}

int send_text (struct sockets *sockets, int fd, const char *url, int code,
               int connection_close, void *content, size_t content_len)
{
  return send_http(sockets, fd, url, code, connection_close,
                   "text/plain", content, content_len);
}

int read_http (struct sockets *sockets, struct amplifier *amplifier, int fd)
{
  char buf[8192], *p;
  unsigned int idx = 0;
  int res, connection_close = 0;
#include "rootpage_html.h"
#include "favicon_ico.h"
  char not_found[] = "Not found.\n";
  char bad_request[] = "Bad Request.\n";

  while (idx < sizeof(buf) - 1) {
    res = read(fd, &buf[idx], sizeof(buf) - idx - 1);
    if (res <= 0) {
      sockets_close(sockets, fd);
      return res;
    }

    idx += res;
    buf[idx] = '\0';

    if (!strstr(buf, "\r\n\r\n"))
      continue;

    connection_close = (strcasestr(buf, "\r\nConnection: close\r\n") != NULL);

    if (!strncasecmp(buf, "GET / ", strlen("GET / ")))
      return send_http(sockets, fd, "/", 200, connection_close,
                       "text/html; charset=utf8", rootpage_html,
                       sizeof(rootpage_html));

    if (!strncasecmp(buf, "GET /favicon.ico ", strlen("GET /favicon.ico ")))
      return send_http(sockets, fd, "/favicon.ico", 200, connection_close,
                       "image/x-icon", favicon_ico, sizeof(favicon_ico));

    if (!strncasecmp(buf, "GET /getstatus ", strlen("GET /getstatus ")))
      return send_status(sockets, fd, "/getstatus", connection_close, amplifier);

    /* TODO */

    p = strchr(buf, '\r');
    *p = '\0';

    return send_text(sockets, fd, buf, 404, connection_close, not_found,
                     sizeof(not_found) - 1);
  }

  return send_text(sockets, fd, "", 400, connection_close, bad_request,
                   sizeof(bad_request) - 1);
}

int handle_client (struct sockets *sockets, struct amplifier *amplifier,
                   int fd)
{
  int newfd;
  union address addr;
  socklen_t addr_len;
  const char *err;

  if (sockets->conns[fd].type == LISTEN) {
    do {
      addr_len = sizeof(addr);
      newfd = accept(fd, &addr.saddr, &addr_len);
    } while ((newfd < 0) && (errno == EINTR));

    if (newfd < 0) {
      log_warn("accept(): %s", strerror(errno));
      return newfd;
    }

    err = sockets_add(sockets, newfd, CLIENT);
    if (err) {
      log_warn("%s", err);
      close(newfd);
      return 0;
    }

    client_address(sockets, newfd, addr);
  }
//  if (sockets->conns[fd].type == AMP)
  if (sockets->conns[fd].type == CLIENT)
    return read_http(sockets, amplifier, fd);

  return 0;
}

int wait_for_client (struct sockets *sockets, struct amplifier *amplifier)
{
  int i, ready, res;
  fd_set rfds;
  struct timeval timeout, *top;

  FD_ZERO(&rfds);
  for (i = 0; i < sockets->num_conns; i++)
    if (sockets->conns[i].type != FREE)
      FD_SET(i, &rfds);

  timeout.tv_sec = 0;
  timeout.tv_usec = 500000;

  top = (amplifier->queue.start != amplifier->queue.end ? &timeout : NULL);
  ready = select(sockets->num_conns, &rfds, NULL, NULL, top);
  if (ready < 0) {
    if (errno == EINTR)
      return 0;

    log_error("select(): %s", strerror(errno));
    return ready;
  }

  for (i = 0; ready && (i < sockets->num_conns); i++) {
    if (FD_ISSET(i, &rfds)) {
      ready--;
      if ((res = handle_client(sockets, amplifier, i)))
        return res;
    }
  }

  return 0;
}

void show_help ()
{
  puts(
"ampctrld version " AMPCTRLD_VERSION "\n"
"\n"
"Usage:\n"
"ampctrld [-d] [-l <address[:port]>] [-p <pid file>] [-u <user>]\n"
"         [<amplifier[:port]>]\n"
"ampctrld -h\n"
"\n"
"  -d                     run in foreground, and log to stdout/stderr, do "
                                                                       "not\n"
"                         detach from terminal, do not log to syslog\n"
"  -l <address[:port]>    listen on this address and port; a maximum of "
                                                STR(MAX_CONNS) "\n"
"                         addresses may be specified; port defaults to "
                                                            DEFAULT_PORT ";\n"
"                         default: " DEFAULT_ADDRESS ":" DEFAULT_PORT "\n"
"  -p <pidfile>           daemonize and save pid to this file; no default, "
                                                                       "pid\n"
"                         gets not written to any file unless <pidfile> is "
                                                                     "given\n"
"  -u <user>              switch to this user; no default, run as invoking "
                                                                      "user\n"
"\n"
"  <amplifier[:port]>     connect to this amplifier; default: " AMP_HOST ":"
                                                                 AMP_PORT "\n"
"\n"
"  -h                     show this help ;-)\n"
);
}

int main (int argc, char **argv)
{
  int res, foreground = 0;
  char *address, *port, *pidfile = NULL;
  const char *err;
  const struct passwd *user = NULL;
  struct sockets sockets;
  struct amplifier amplifier;

  sockets_init(&sockets);
  amplifier_init(&amplifier);

  while ((res = getopt(argc, argv, "dhl:p:u:")) != -1) {
    switch (res) {
      case 'd': foreground = 1; break;
      case 'h': show_help(); return 0;
      case 'l':
        err = parse_address(optarg, &address, &port, DEFAULT_PORT);
        if (err)
          errx(1, "%s: %s", optarg, err);

        res = create_listen_socket_inet(address, port);
        if ((err = sockets_add(&sockets, res, LISTEN)))
          errx(1, "%s", err);

        break;
      case 'p': pidfile = optarg; break;
      case 'u': user = get_user(optarg); break;
      default: errx(1, "Unknown option '%c'. See -h for help.", optopt);
    }
  }

  if (optind < argc) {
    err = parse_address(argv[optind], &amplifier.host, &amplifier.port,
                        AMP_PORT);
    if (err)
      errx(1, "%s: %s", argv[optind], err);
  }

  if (!sockets.num_conns) {
    res = create_listen_socket_inet(DEFAULT_ADDRESS, DEFAULT_PORT);
    if ((err = sockets_add(&sockets, res, LISTEN)))
      errx(1, "%s", err);
  }

  if (!foreground)
    daemonize();

  if (pidfile)
    save_pidfile(pidfile);

  if (user)
    change_user(user);

  setup_signals();

  if (!foreground) {
    openlog("ampctrld", LOG_NDELAY|LOG_PID, LOG_DAEMON);
    log_to_syslog = 1;
    close(0); close(1); close(2);
  }

  log_info("starting...");

#ifdef USE_SYSTEMD
  sd_notify(0, "READY=1");
#endif

  while (running) {
    res = wait_for_client(&sockets, &amplifier);
    if (res < 0)
      running = 0;
  }

  for (res = 0; res < sockets.num_conns; res++)
    sockets_close(&sockets, res);

  if (pidfile)
    unlink(pidfile); /* may fail, e.g. due to changed user privs */

  log_info("exiting...");
  if (log_to_syslog)
    closelog();

  return 0;
}
