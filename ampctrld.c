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

#define AMPCTRLD_VERSION     "2"

#define DEFAULT_ADDRESS      "0.0.0.0"
#define DEFAULT_PORT         "8082"
#define MAX_LISTEN_ADDRESSES 16

#define AMP_HOST             "onkyo"
#define AMP_PORT             "60128"
const char* AMP_INPUTS[] = { "10", "DVD",     \
                             "00", "VCR/DVR", \
                             "01", "CBL/SAT", \
                             "02", "GAME/TV", \
                             "03", "AUX1",    \
                             "04", "AUX2",    \
                             "20", "TAPE",    \
                             "24", "TUNER",   \
                             "23", "CD",      \
                             "22", "PHONO",   \
                             "28", "NET/USB" };

const char* AMP_NETUSBCMDS[] = { "play",   \
                                 "stop",   \
                                 "select", \
                                 "return", \
                                 "down",   \
                                 "up",     \
                                 "left",   \
                                 "right",  \
                                 "0",      \
                                 "1",      \
                                 "2",      \
                                 "3",      \
                                 "4",      \
                                 "5",      \
                                 "6",      \
                                 "7",      \
                                 "8",      \
                                 "9" };

#define MAX_CONNS            FD_SETSIZE
#define QUEUE_LEN            8
#define CMD_LEN              28

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

#define startswith(str, needle) strncasecmp(str, needle, strlen(needle))==0

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
#define INETADDR_STRLEN (INET6_ADDRSTRLEN + 8)
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
    char clientname[INETADDR_STRLEN];
  } conns[MAX_CONNS];
};

struct command {
  unsigned char cmd[CMD_LEN];
  int len;
  int rxwait;
};

struct queue {
  int start;
  int end;
  struct command entries[QUEUE_LEN];
};

struct amplifier {
  char *host;
  char *port;
  char addr[INETADDR_STRLEN];
  int socket;
  int txready;
  int rxwait;
  int power;
  int mute;
  int volume;
  int input;
  const char* inputs[sizeof(AMP_INPUTS)/sizeof(AMP_INPUTS[0])/2][2];
  char inputs_json[1024];
  int inputs_jlen;
  struct queue queue;
};

/* used by main() and quitterm_handler() */
static int running = 1;
/* used by main() and log_*() macros */
static int log_to_syslog = 0;

int write_all (const int socket, const void* const buf, const size_t len)
{       
  size_t written_bytes;
  ssize_t res;
  
  for (written_bytes = 0; written_bytes < len; written_bytes += res) {
    res = write(socket, buf + written_bytes, len - written_bytes);
    if (res <= 0) {
      if (errno != EINTR)
        return -1;
      res = 0;
    }
  } 
    
  return 0;
}   
    
void quitterm_handler (const int sig)
{ 
  if (sig == SIGTERM)  
    log_info("SIGTERM received, going down...");
    
  running = 0;
}

void setup_signal (const int sig, void (*handler)(int))
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

const struct passwd *get_user (const char* const username)
{
  const struct passwd *pw = getpwnam(username);

  if (!pw)
    errx(1, "no such user: %s", username);

  return pw;
}

const char *create_client_socket_inet (const char* const addr,
                                       const char* const port,
                                       int* const client_socket)
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
        connect(*client_socket, walk->ai_addr, walk->ai_addrlen)) {
      close(*client_socket);
      *client_socket = -1;
    } else {
      break;
    }
  }

  if (!walk)
    err = strerror(errno);

  freeaddrinfo(result);

  return err;
}

int create_listen_socket_inet (const char* const ip, const char* const port)
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

void save_pidfile (const char* const pidfile)
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

void change_user (const struct passwd* const pw)
{
  if (initgroups(pw->pw_name, pw->pw_gid))
    err(1, "initgroups()");
  if (setgid(pw->pw_gid))
    err(1, "setgid()");
  if (setuid(pw->pw_uid))
    err(1, "setuid()");
}

void client_address (struct sockets* const sockets, const int fd,
                     const union address uaddr)
{
  char addr[INET6_ADDRSTRLEN];
  const struct sockaddr_in *sin;
  const struct sockaddr_in6 *sin6;

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

const char *parse_address (char* const ip46_port, char** const addr,
                           char** const port, char* const default_port)
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
    *port = default_port;
  else {
    *port = closing_bracket + 1;
    *closing_bracket = '\0';
  }

  return NULL;
}

void addrport (const char* const addr, const char* const port,
               char result[INETADDR_STRLEN])
{
  if (strchr(addr, ':'))
    snprintf(result, INETADDR_STRLEN, "[%s]:%s", addr, port);
  else
    snprintf(result, INETADDR_STRLEN, "%s:%s", addr, port);
}

void sockets_init (struct sockets* const sockets)
{
  int i;

  sockets->num_conns = 0;
  for (i = 0; i < MAX_CONNS; i++)
    sockets->conns[i].type = FREE;
}

const char *sockets_add (struct sockets* const sockets, const int fd,
                         const enum conntype type)
{
  if (fd >= MAX_CONNS)
    return "socket descriptor too big, maximum is " STR(MAX_CONNS);

  sockets->conns[fd].type = type;
  if (fd >= sockets->num_conns)
    sockets->num_conns = fd + 1;

  return NULL;
}

void sockets_close (struct sockets* const sockets, int fd)
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

void queue_flush (struct queue* const queue)
{
  queue->start = 0;
  queue->end = 0;
}

int queue_empty (struct queue* const queue)
{
  return (queue->start == queue->end);
}

int queue_push (struct queue* const queue)
{
  int ret = queue->end;

  if (++queue->end >= QUEUE_LEN)
    queue->end = 0;

  if (queue->end == queue->start)
    log_warn("%s", "queue overflow");

  return ret;
}

int queue_shift (struct queue* const queue)
{
  int ret;

  if (queue_empty(queue))
    return -1;

  ret = queue->start;
  if (++queue->start >= QUEUE_LEN)
    queue->start = 0;

  return ret;
}

int netusbcmd (const char* const ntc)
{
  size_t i;

  for (i = 0; i < sizeof(AMP_NETUSBCMDS)/sizeof(AMP_NETUSBCMDS[0]); i++)
    if (!strcmp(AMP_NETUSBCMDS[i], ntc))
      return i;

  return -1;
}

void amplifier_init (struct amplifier* const amplifier)
{
  size_t i;

  amplifier->host = AMP_HOST;
  amplifier->port = AMP_PORT;
  addrport(AMP_HOST, AMP_PORT, &amplifier->addr[0]);
  amplifier->socket = -1;
  amplifier->txready = 0;
  amplifier->rxwait = 0;
  amplifier->power = 0;
  amplifier->mute = 0;
  amplifier->volume = 0;
  amplifier->input = -1;
  for (i = 0; i < sizeof(AMP_INPUTS)/sizeof(AMP_INPUTS[0]); i++)
    amplifier->inputs[i / 2][i % 2] = AMP_INPUTS[i];
  queue_flush(&amplifier->queue);
}

int volume_in_range (const int volume)
{
  return ((volume > -82) && (volume <= -25));
}

int volume_to_amplifier (const int volume)
{
  return volume + 82;
}

int amplifier_to_volume (const int ampvol)
{
  return ampvol - 82;
}

int input_slot (struct amplifier* const amplifier, const char* const input)
{
  size_t i;

  for (i=0; i<sizeof(amplifier->inputs)/sizeof(amplifier->inputs[0]); i++)
    if (!strcmp(amplifier->inputs[i][0], input))
      return i;

  return -1;
}

const char *amplifier_input (struct amplifier* const amplifier,
                             const char* const assignment)
{
  char *name;
  int slot;

  name = strchr(assignment, '=');
  if (!name)
    return "no '=' in input assignment";

  *name++ = '\0';
  slot = input_slot(amplifier, assignment);
  if (slot < 0)
    return "unknown input assignment";

  amplifier->inputs[slot][1] = name;
  return NULL;
}

void amplifier_inputs (struct amplifier* const amplifier)
{
  size_t i, len = 0;

  for (i=0; i<sizeof(amplifier->inputs)/sizeof(amplifier->inputs[0]); i++)
    len += snprintf(&amplifier->inputs_json[len],
                    sizeof(amplifier->inputs_json) - len,
                    "%c\"%s\":\"%s\"",
                    (i ? ',' : '{'), amplifier->inputs[i][0],
                    amplifier->inputs[i][1]);

  len += snprintf(&amplifier->inputs_json[len],
                  sizeof(amplifier->inputs_json) - len,
                  "}\n");
  amplifier->inputs_jlen = len;
}

int amplifier_connected (struct amplifier* const amplifier)
{
  return (amplifier->socket >= 0);
}

void amplifier_enqueue (struct amplifier* const amplifier,
                        const char* const cmd)
{
  int slot, i;
  size_t cmdlen, cmdlen3;

  if (!amplifier_connected(amplifier))
    return;

  cmdlen = strlen(cmd);
  cmdlen3 = 2 + cmdlen + 1;
  if (cmdlen + 18 >= CMD_LEN) {
    log_warn("command too long: %s", cmd);
    return;
  }

  slot = queue_push(&amplifier->queue);
  amplifier->queue.entries[slot].cmd[0] = 'I';
  amplifier->queue.entries[slot].cmd[1] = 'S';
  amplifier->queue.entries[slot].cmd[2] = 'C';
  amplifier->queue.entries[slot].cmd[3] = 'P';
  amplifier->queue.entries[slot].cmd[4] = 0;
  amplifier->queue.entries[slot].cmd[5] = 0;
  amplifier->queue.entries[slot].cmd[6] = 0;
  amplifier->queue.entries[slot].cmd[7] = 16;
  for (i = 11; i >= 8; i--) {
    amplifier->queue.entries[slot].cmd[i] = cmdlen3 % 256;
    cmdlen3 /= 256;
  }
  amplifier->queue.entries[slot].cmd[12] = 1;
  amplifier->queue.entries[slot].cmd[13] = 0;
  amplifier->queue.entries[slot].cmd[14] = 0;
  amplifier->queue.entries[slot].cmd[15] = 0;
  amplifier->queue.entries[slot].cmd[16] = '!';
  amplifier->queue.entries[slot].cmd[17] = '1';
  for (i = cmdlen - 1; i >= 0; i--) {
    amplifier->queue.entries[slot].cmd[18 + i] = cmd[i];
  }
  amplifier->queue.entries[slot].cmd[18 + cmdlen] = '\r';
  amplifier->queue.entries[slot].len = 18 + cmdlen + 1;
  amplifier->queue.entries[slot].rxwait = ((cmdlen <= 2) ||
                                           (cmd[0] != 'N') ||
                                           (cmd[1] != 'T') ||
                                           (cmd[2] != 'C'));
}

const char *amplifier_connect (struct sockets* const sockets,
                               struct amplifier* const amplifier)
{
  const char *err;

  if (amplifier_connected(amplifier))
    return NULL;

  addrport(amplifier->host, amplifier->port, amplifier->addr);

  err = create_client_socket_inet(amplifier->host, amplifier->port,
                                  &amplifier->socket);
  if (err)
    goto AMPCONN_ERR0;

  err = sockets_add(sockets, amplifier->socket, AMP);
  if (err)
    goto AMPCONN_ERR1;

  amplifier->txready = 0;
  amplifier->rxwait = 0;
  queue_flush(&amplifier->queue);

  amplifier_enqueue(amplifier, "PWRQSTN");
  amplifier_enqueue(amplifier, "MVLQSTN");
  amplifier_enqueue(amplifier, "AMTQSTN");
  amplifier_enqueue(amplifier, "SLIQSTN");

  return NULL;

AMPCONN_ERR1:
  close(amplifier->socket);
  amplifier->socket = -1;

AMPCONN_ERR0:
  log_warn("cannot connect to %s: %s", amplifier->addr, err);

  return err;
}

void amplifier_send (struct sockets* const sockets,
                     struct amplifier* const amplifier)
{
  int slot, res;

  if (!amplifier_connected(amplifier) ||
      !amplifier->txready ||
      amplifier->rxwait)
    return;

  if ((slot = queue_shift(&amplifier->queue)) < 0)
    return;

  amplifier->rxwait = amplifier->queue.entries[slot].rxwait;
  res = write_all(amplifier->socket,
                  amplifier->queue.entries[slot].cmd,
                  amplifier->queue.entries[slot].len);
  if (res) {
    log_warn("cannot send data to %s: %s", amplifier->addr, strerror(errno));
    sockets_close(sockets, amplifier->socket);
    amplifier->socket = -1;
  }

  amplifier->txready = 0;
}

const char *http_reason (const int code)
{
  switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    default:  return "<Unknown HTTP Code>";
  }
}

void send_http (struct sockets* const sockets, const int fd,
                const char* const url, const int code,
                const int connection_close, const char* const content_type,
                void* const content, const size_t content_len)
{
  char header[512];
  int hdr_len, len, res;
  struct iovec iov[2];

  log_info("%s \"%s\" %i", sockets->conns[fd].clientname, url, code);

  hdr_len = snprintf(header, sizeof(header),
                     "HTTP/1.1 %i %s\r\n"
                     "Server: ampctrld/version " AMPCTRLD_VERSION "\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %lu\r\n"
                     "%s"
                     "\r\n",
                     code, http_reason(code), content_type, content_len,
                     (connection_close ? "Connection: close\r\n" : ""));

  iov[0].iov_base = header;
  iov[0].iov_len = hdr_len;
  iov[1].iov_base = content;
  iov[1].iov_len = content_len;
  len = hdr_len + content_len;

  res = writev(fd, iov, 2);
  if (res < 0) {
    log_warn("cannot send data to %s: %s", sockets->conns[fd].clientname,
             strerror(errno));
    sockets_close(sockets, fd);
    return;
  }
  if (res != len) {
    log_warn("sent only %i of %i bytes to %s: ", res, len,
             sockets->conns[fd].clientname);
    sockets_close(sockets, fd);
    return;
  }
  if (connection_close)
    sockets_close(sockets, fd);
}

const char *bool2json (const int b)
{
  return (b ? "true" : "false");
}

void send_text (struct sockets* const sockets, const int fd,
                const char* const url, const int code,
                const int connection_close, void* const content,
                const size_t content_len)
{
  send_http(sockets, fd, url, code, connection_close, "text/plain",
            content, content_len);
}

void send_status (struct sockets* const sockets, const int fd,
                  const char* const url, const int connection_close,
                  struct amplifier* const amplifier)
{
  char status[128];
  int len;

  len = snprintf(status, sizeof(status), "{"
                 "\"connected\": %s, "
                 "\"power\": %s, "
                 "\"mute\": %s, "
                 "\"volume\": %i, "
                 "\"input\": \"%s\"}\n",
                 bool2json(amplifier_connected(amplifier)),
                 bool2json(amplifier->power),
                 bool2json(amplifier->mute),
                 amplifier->volume,
                 (amplifier->input < 0 ? "" :
                  amplifier->inputs[amplifier->input][0]));

  send_http(sockets, fd, url, 200, connection_close, "application/json",
            status, len);
}

void send_reconnect (struct sockets* const sockets, const int fd,
                     const char* const url, const int connection_close,
                     struct amplifier* const amplifier)
{
  char ok[] = "OK.\n";
  const char *err;
  char buf[128];
  int len;

  err = amplifier_connect(sockets, amplifier);
  if (err) {
    len = snprintf(buf, sizeof(buf), "%s: %s.\n", amplifier->addr, err);
    send_text(sockets, fd, url, 502, connection_close, buf, len);
  } else {
    send_text(sockets, fd, url, 200, connection_close, ok, sizeof(ok));
  }
}

int send_set (const char* const url, struct amplifier* const amplifier)
{
  const char *query;
  char *p;
  char cmd[CMD_LEN];
  int volume, slot, i;
  size_t len;

  query = strchr(url, '?') + 1;
  if ((p = strchr(query, ' ')))
    *p = '\0';
  else
    return 0;

  if (!strcmp(query, "power=true")) {
    amplifier_enqueue(amplifier, "PWR01");
  }
  else if (!strcmp(query, "power=false")) {
    amplifier_enqueue(amplifier, "PWR00");
  }
  else if (!strcmp(query, "mute=true")) {
    amplifier_enqueue(amplifier, "AMT01");
  }
  else if (!strcmp(query, "mute=false")) {
    amplifier_enqueue(amplifier, "AMT00");
  }
  else if (startswith(query, "volume=") &&
           ((volume = strtol(query + 7, NULL, 10))) &&
           volume_in_range(volume)) {
    snprintf(cmd, sizeof(cmd), "MVL%02X", volume_to_amplifier(volume));
    amplifier_enqueue(amplifier, cmd);
  }
  else if (startswith(query, "input=") &&
           ((slot = input_slot(amplifier, query + 6)) >= 0)) {
    snprintf(cmd, sizeof(cmd), "SLI%s", amplifier->inputs[slot][0]);
    amplifier_enqueue(amplifier, cmd);
  }
  else if (startswith(query, "ntc=") &&
           ((slot = netusbcmd(query + 4)) >= 0) &&
           ((len = snprintf(cmd, sizeof(cmd), "NTC%s",
                            AMP_NETUSBCMDS[slot])) < sizeof(cmd))) {
    for (i = len - 1; i >= 3; i--)
      cmd[i] = toupper(cmd[i]);
    amplifier_enqueue(amplifier, cmd);
  }
  else {
    return 0;
  }

  return 1;
}

void read_http (struct sockets* const sockets,
                struct amplifier* const amplifier, const int fd)
{
  char buf[8192], *p;
  unsigned int idx = 0;
  int res, connection_close = 0;
#include "rootpage_html.h"
#include "favicon_ico.h"
  char ok[] = "OK.\n";
  char not_found[] = "Not found.\n";
  char bad_request[] = "Bad request.\n";

  while (idx < sizeof(buf) - 1) {
    res = read(fd, &buf[idx], sizeof(buf) - idx - 1);
    if (res < 0) {
      log_warn("cannot read data from %s: %s", sockets->conns[fd].clientname,
               strerror(errno));
      sockets_close(sockets, fd);
      return;
    }
    if (!res) {
      sockets_close(sockets, fd);
      return;
    }

    idx += res;
    buf[idx] = '\0';

    if (!strstr(buf, "\r\n\r\n"))
      continue;

    connection_close = (strcasestr(buf, "\r\nConnection: close\r\n") != NULL);

    if (startswith(buf, "GET /getstatus "))
      send_status(sockets, fd, "/getstatus", connection_close, amplifier);

    else if (startswith(buf, "GET /set?") &&
             send_set(buf, amplifier))
      send_text(sockets, fd, buf + 4, 200, connection_close, ok, sizeof(ok));

    else if (startswith(buf, "GET /getinputs "))
      send_http(sockets, fd, "/getinputs", 200, connection_close,
                "application/json", amplifier->inputs_json,
                amplifier->inputs_jlen);

    else if (startswith(buf, "GET /reconnect "))
      send_reconnect(sockets, fd, "/reconnect", connection_close, amplifier);

    else if (startswith(buf, "GET /favicon.ico "))
      send_http(sockets, fd, "/favicon.ico", 200, connection_close,
                "image/x-icon", favicon_ico, sizeof(favicon_ico));

    else if (startswith(buf, "GET / "))
      send_http(sockets, fd, "/", 200, connection_close,
                "text/html; charset=utf8", rootpage_html,
                sizeof(rootpage_html));

    else {
      p = strchr(buf, '\r');
      *p = '\0';
      send_text(sockets, fd, buf, 404, connection_close, not_found,
                sizeof(not_found));
    }

    return;
  }

  send_text(sockets, fd, "", 400, connection_close, bad_request,
            sizeof(bad_request));
}

int accept_client (struct sockets* const sockets, const int fd)
{
  int newfd;
  union address addr;
  socklen_t addr_len;
  const char *err;

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

  return 0;
}

void read_amplifier (struct sockets* const sockets,
                     struct amplifier* const amplifier, const int fd)
{
  ssize_t datalen;
  char data[CMD_LEN];
  long cmdlen;
  size_t i;
  int volume = 0;

  datalen = read(fd, data, sizeof(data));
  if (datalen < 0)
    log_warn("cannot read data from %s: %s",
             amplifier->addr, strerror(errno));
  if (datalen <= 0) {
    sockets_close(sockets, fd);
    amplifier->socket = -1;
    return;
  }

  amplifier->rxwait = 0;

  if (datalen < 20) {
    log_warn("received short packet from %s: %lu", amplifier->addr, datalen);
    return;
  }

  cmdlen = ((data[8] * 256 + data[9]) * 256 + data[10]) * 256 + data[11] - 4;
  if ((data[0] != 'I') || (data[1] != 'S') ||
      (data[2] != 'C') || (data[3] != 'P') ||
      (data[4] != 0) || (data[5] != 0)  ||
      (data[6] != 0) || (data[7] != 16) ||
      (data[12] != 1) || (data[13] != 0) ||
      (data[14] != 0) || (data[15] != 0) ||
      (data[16] != '!') || (data[17] != '1') ||
      (data[datalen - 2] != 0x1a) || (data[datalen - 1] != '\r') ||
      (cmdlen < 0) || (cmdlen + 20 > datalen)) {
    log_warn("received bogus packet from %s", amplifier->addr);
    return;
  }

  data[datalen - 2] = '\0';

  if (!strcmp(&data[18], "PWR00")) amplifier->power = 0;
  else if (!strcmp(&data[18], "PWR01")) amplifier->power = 1;
  else if (!strcmp(&data[18], "AMT00")) amplifier->mute = 0;
  else if (!strcmp(&data[18], "AMT01")) amplifier->mute = 1;
  else if (!strncmp(&data[18], "MVL", 3)) {
    volume = amplifier_to_volume(strtol(&data[21], NULL, 16));
    if (volume_in_range(volume))
      amplifier->volume = volume;
  } else if (!strncmp(&data[18], "SLI", 3)) {
    for (i=0; i<sizeof(amplifier->inputs)/sizeof(amplifier->inputs[0]); i++)
      if (!strcmp(amplifier->inputs[i][0], &data[21]))
        amplifier->input = i;
  } else if (strcmp(&data[18], "NTC")) {
    log_warn("received unknown command from %s: %s",
             amplifier->addr, &data[18]);
  }
}

int handle_client (struct sockets* const sockets,
                   struct amplifier* const amplifier, const int fd)
{
  if (sockets->conns[fd].type == CLIENT)
    read_http(sockets, amplifier, fd);

  else if (sockets->conns[fd].type == AMP)
    read_amplifier(sockets, amplifier, fd);

  else if (sockets->conns[fd].type == LISTEN)
    return accept_client(sockets, fd);

  return 0;
}

int wait_for_client (struct sockets* const sockets,
                     struct amplifier* const amplifier)
{
  int i, ready, res;
  fd_set rfds, wfds;
  struct timeval timeout, *top;

  FD_ZERO(&rfds);
  FD_ZERO(&wfds);

  for (i = 0; i < sockets->num_conns; i++)
    if (sockets->conns[i].type != FREE)
      FD_SET(i, &rfds);

  if (amplifier_connected(amplifier) && !amplifier->txready)
    FD_SET(amplifier->socket, &wfds);

  timeout.tv_sec = 0;
  timeout.tv_usec = 500000;

  top = (queue_empty(&amplifier->queue) ? NULL : &timeout);
  ready = select(sockets->num_conns, &rfds, &wfds, NULL, top);
  if (ready < 0) {
    if (errno == EINTR)
      return 0;

    log_error("select(): %s", strerror(errno));
    return ready;
  }

  if (amplifier_connected(amplifier) && FD_ISSET(amplifier->socket, &wfds)) {
    amplifier->txready = 1;
    ready--;
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
"ampctrld [-d] [-i <id>=<name>] [-l <address>[:<port>]] [-p <pid file>]\n"
"         [-u <user>] [<amplifier>[:<port>]]\n"
"ampctrld -a\n"
"ampctrld -h\n"
"\n"
"  -d                       run in foreground, and log to stdout/stderr, do "
                                                                       "not\n"
"                           detach from terminal, do not log to syslog\n"
"  -i <id>=<name>           assign <name> to input <id>;\n"
"                           may be specified multiple times\n"
"  -l <address>[:<port>]    listen on this address and port; a maximum of "
                                                STR(MAX_LISTEN_ADDRESSES) "\n"
"                           addresses may be specified; port defaults to "
                                                            DEFAULT_PORT ";\n"
"                           default: " DEFAULT_ADDRESS ":" DEFAULT_PORT "\n"
"  -p <pidfile>             daemonize and save pid to this file; no default, "
                                                                       "pid\n"
"                           gets not written to any file unless <pidfile> is "
                                                                     "given\n"
"  -u <user>                switch to this user; no default, run as invoking "
                                                                      "user\n"
"\n"
"  <amplifier>[:<port>]     connect to this amplifier; default: " AMP_HOST ":"
                                                                 AMP_PORT "\n"
"\n"
"  -a                       show default input names\n"
"  -h                       show this help ;-)\n");
}

void show_input_names ()
{
  size_t i;

  puts("Default input names:\n");
  for (i = 0; i < sizeof(AMP_INPUTS)/sizeof(AMP_INPUTS[0]); i += 2)
    printf("  %s = %s\n", AMP_INPUTS[i], AMP_INPUTS[i + 1]);
  puts("");
}

int main (int argc, char* const * const argv)
{
  int res, foreground = 0;
  char *address, *port, *pidfile = NULL;
  const char *err;
  const struct passwd *user = NULL;
  struct sockets sockets;
  struct amplifier amplifier;

  sockets_init(&sockets);
  amplifier_init(&amplifier);

  while ((res = getopt(argc, argv, "adhi:l:p:u:")) != -1) {
    switch (res) {
      case 'a': show_input_names(); return 0;
      case 'd': foreground = 1; break;
      case 'h': show_help(); return 0;
      case 'i':
        err = amplifier_input(&amplifier, optarg);
        if (err)
          errx(1, "%s: %s", optarg, err);
        break;
      case 'l':
        /* stdin, stdout, stderr = 3 open descriptors */
        if (sockets.num_conns >= MAX_LISTEN_ADDRESSES + 3)
          errx(1, "too many addresses to listen on");

        err = parse_address(optarg, &address, &port, DEFAULT_PORT);
        if (err)
          errx(1, "%s: %s", optarg, err);

        res = create_listen_socket_inet(address, port);
        if ((err = sockets_add(&sockets, res, LISTEN)))
          errx(1, "%s: %s", optarg, err);

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
  amplifier_inputs(&amplifier);

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

    amplifier_send(&sockets, &amplifier);
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
