# ampctrld

ampctrld is a webserver to control an Onkyo receiver or amplifier. See https://ogris.de/ampcontrol/

## Compile

1. tar xf ampctrld-xx.tar.bz2

2. cd ampctrld-xx

3. make

4. make install

You now have /usr/local/etc/rc.d/ampctrld on FreeBSD, and /lib/systemd/system/ampctrld.service or /etc/init.d/ampctrld on a Linux with systemd or OpenRC, respectively.

## Usage

```
ampctrld version 1

Usage:
ampctrld [-d] [-i <id>=<name>] [-l <address>[:<port>]] [-p <pid file>]
         [-u <user>] [<amplifier>[:<port>]]
ampctrld -a
ampctrld -h

  -d                       run in foreground, and log to stdout/stderr, do not
                           detach from terminal, do not log to syslog
  -i <id>=<name>           assign <name> to input <id>;
                           may be specified multiple times
  -l <address>[:<port>]    listen on this address and port; a maximum of 1024
                           addresses may be specified; port defaults to 8082;
                           default: 0.0.0.0:8082
  -p <pidfile>             daemonize and save pid to this file; no default, pid
                           gets not written to any file unless <pidfile> is given
  -u <user>                switch to this user; no default, run as invoking user

  <amplifier>[:<port>]     connect to this amplifier; default: onkyo:60128

  -a                       show default input names
  -h                       show this help ;-)

```

## Screenshot

The web interface runs on port 8082 by default:

![ampctrld](https://ogris.de/ampcontrol/ampctrld.png)

