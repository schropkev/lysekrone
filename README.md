# `lysekrone`: LD_PRELOAD client library for xsocket.

`lysekrone` is a LD_PRELOAD client library for xsocket, it differs from original `libxbind.so` for being more sophisticated and by having ability to handle outgoing connections

## Build

This project uses [Meson](https://mesonbuild.com/), the build files are provided by `xsocket` itself. You will also have to install `patch`, `git`, standard C compilation tools and `libc6-dev` (on other systems, `glibc-devel`).

```
git clone https://github.com/koro666/xsocket
cd xsocket
git clone https://github.com/schropkev/lysekrone
cp ./lysekrone/lysekrone.c .
patch ./meson.build < ./lysekrone/meson.build.patch
meson setup build
meson compile -C build
```

Alternatively, if on Archlinux, just run `makepkg` to build a proper package.

The LD_PRELOAD library will be located at `./buid/liblysekrone.so`, but if you wish to install along with `xsocket`, just type:

`sudo meson install -C build`

## Usage

The LD_PRELOAD library uses groups of destinations that will use their own `xsocket-server` Unix sockets, each group is inside parenthesis `(...)`, there can be multiple groups with multiple destinations, each destination or list of destinations can use their own `xsocket-server` Unix sockets.

The syntax is:

```
LD_PRELOAD="./buid/liblysekrone.so" LK_BIND_MAP="(destination1,destination2 /path/to/xsocket/socket),(destination3,destination4 @xsocket-abstract-socket)" \
   LK_CONN_MAP="(destination1,destination2 /path/to/xsocket/socket),(destination3,destination4 @xsocket-abstract-socket)"
```

`LK_BIND_MAP` is meant for binding connections by intercepting `bind()` syscall (incoming connections) and `LK_CONN_MAP` is meant for intercepting `connect()/sendto()/sendmsg()/sendmmsg()` (outgoing connections).

A destination can be:

- IPv4/IPv6 addresses with normal ports, such as `127.0.0.1:1234` and `[::1]:1234`. IPv6 addresses must be `[bracketed]`.
- IPv4/IPv6 addresses with port ranges, such as `127.0.0.1:12345-20000` and `[::1]:12345-20000`..
- IPv4/IPv6 addresses with port wildcards (meaning matching every port in the address), such as `10.0.0.1:*` and `[fc00::1]:*`.
- IPv4 CIDRs, such as `192.168.1.0/24`.
- IPv6 scopes, such as `2001:db8::/32` (these should not be bracketed).
- IPv6 link-local addresses with network interface suffixes plus a port, port range or a port wildcard, such as `[fe80::1%eth0]:1234`, `[fe80::1%eth1]:12345-20000` or `[fe80::1%eth0]:*`.
- A negation (#) of all above schemes, such as `#127.0.0.1:4321` and `#[::1]:4321`. A negation means that the destination will not be handled by the library.
- Global wildcards (*), meaning matching all next destinations in a group.

Rules are read left to right, meaning that if there is 2 matches of same destination, only the first will apply.

For example in the scheme below:

`LK_BIND_MAP=(#127.0.0.0/8,*)`

There is a global wildcard meaning matching all connections, but the destination `127.0.0.1:1234` will not be handled because it matches the negation `#127.0.0.0/8` and rules are read left to right, so the global wildcard will be ignored for this destination.

## How it Works

It works just like `libxbind.so` except that you can specify destination connecting with `LK_CONN_MAP`.

The `liblysekrone.so` library works by intercepting `bind()` (LK_BIND_MAP) or `connect()/sendto()/sendmsg()/sendmmsg()` (LK_CONN_MAP) syscalls, creating a new socket of the same domain, type and protocol as the original, copying all known socket options, and then duplicating it over the original file descriptor. Special care is taken that the non-blocking and close-on-exec flags of the original socket are preserved.

All calls to `setsockopt` are also tracked to keep track of which socket options have been used, in order to minimize the amount of blind copying of socket options.

--------------------

`xsocket` tools ( `xsocket-server` and `libxbind`) as well as `lysekrone` work with network namespaces as they are intended, but they also works with [VRFs](https://docs.kernel.org/networking/vrf.html), containers (such as `LXC` and `Docker`), sandboxes (such as `Firejail` and `Bubblewrap`) and even `cgroups` (assuming the sockets opened by `xsocket-server` will be marked or handled in some way by kernel's `Netfilter`).

If the VRF interface is in the same network namespace (usually the host) as of the program to be tricked with `libxbind.so` or `liblysekrone.so`, just using an abstract Unix socket is enough as AF_UNIX sockets are not bound to the `VRF` themselves. If the VRF is inside a other network namespace than the `libxbind.so` or `liblysekrone.so`, Unix sockets files should be used instead of abstract ones.

For containers which support bind mounts, an user for running `xsocket-server` can be added with certain UID and another same user with same UID can be created inside the container; correct permissions (chmod 0700 is enough) must be set in the host side on shared folder; so another users inside the host system and container itself cannot sniff the `xsocket-server` Unix socket file; of course, root always can. Another way is creating an user for `xsocket-server` with certain UID and restricting the permissions of folder that will have the Unix socket to user itself (chmod 0700), and also in the host side, modify the ACL of the folder allowing the specific UID inside the container to see and write to Unix socket file.

For sandboxes, any folder can be used assuming it's writable and accessible by the user that `libxbind.so` / `liblysekrone.so` will send the messages to `xsocket-server` inside the sandbox; permissions, ownership's and ACL can play a nice role in this case.

It is possible also to mark `xsocket-server` sockets with firewall marks by using [this script](https://github.com/zhangyoufu/fwmark). Just run `xsocket-server` as an unprivileged user using this script by using `sudo`; all the listening points and outgoing connections will follow the firewall mark specified in the script without needing elevated privileges such as `CAP_NET_ADMIN` (needed for `SO_MARK`).

`sudo ./fwmark.py 123 sudo -u someuser xsocket-server @xs-socket`

--------------------

## Thanks

- [@koro666](https://github.com/koro666) for his awesome project [xsocket](https://github.com/koro666/xsocket).

--------------------

Created on May 21, 2026.
