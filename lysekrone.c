#include "system.h"
#include "cleanup.h"
#include "socket.h"
#include "switch.h"
#include "xsocket.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LK_MAX_TOKEN 256
#define LK_MAX_SOCKOPTS 128
#define LK_MAX_OPTVAL 512

typedef int (*bind_fn)(
        int,
        const struct sockaddr*,
        socklen_t);

typedef int (*connect_fn)(
        int,
        const struct sockaddr*,
        socklen_t);

typedef ssize_t (*sendto_fn)(
        int,
        const void*,
        size_t,
        int,
        const struct sockaddr*,
        socklen_t);

typedef ssize_t (*sendmsg_fn)(
        int,
        const struct msghdr*,
        int);

typedef int (*sendmmsg_fn)(
        int,
        struct mmsghdr*,
        unsigned int,
        int);

typedef int (*setsockopt_fn)(
        int,
        int,
        int,
        const void*,
        socklen_t);

struct lk_match
{
        bool negate;
        bool wildcard;

        int family;

        union
        {
                struct in_addr in;
                struct in6_addr in6;
        } addr;

        uint8_t prefix;

        bool any_port;
        uint16_t port_lo;
        uint16_t port_hi;

        unsigned int ifindex;
};

struct lk_group
{
        struct lk_match* matches;
        size_t nmatches;

        char* socket_path;
};

struct lk_map
{
        struct lk_group* groups;
        size_t ngroups;
};

struct lk_sockopt
{
        int level;
        int optname;

        socklen_t optlen;

        uint8_t value[LK_MAX_OPTVAL];
};

struct lk_socket_state
{
        bool used;

        int fd;

        struct lk_sockopt opts[LK_MAX_SOCKOPTS];
        size_t nopts;
};

static struct lk_map lk_bind_map;
static struct lk_map lk_conn_map;

static volatile bind_fn lk_real_bind;
static volatile connect_fn lk_real_connect;
static volatile sendto_fn lk_real_sendto;
static volatile sendmsg_fn lk_real_sendmsg;
static volatile sendmmsg_fn lk_real_sendmmsg;
static volatile setsockopt_fn lk_real_setsockopt;

static pthread_mutex_t lk_state_lock =
        PTHREAD_MUTEX_INITIALIZER;

static struct lk_socket_state lk_states[1024];

static bool lk_parse_map(const char* text, struct lk_map* map);
static bool lk_parse_group(
        const char* text,
        struct lk_group* group);

static bool lk_parse_match(
        const char* token,
        struct lk_match* out);

static bool lk_match_one(
        const struct lk_match* rule,
        const struct sockaddr* sa);

static const char* lk_match_map(
        const struct lk_map* map,
        const struct sockaddr* sa,
        socklen_t salen);

static bool lk_redirect_socket(
        int fd,
        const char* server);

static void lk_track_sockopt(
        int fd,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen);

static void lk_copy_socket_opts(
        int oldfd,
        int newfd);

static struct lk_socket_state*
lk_get_socket_state(int fd)
{
        for (size_t i = 0;
             i < sizeof(lk_states) /
                 sizeof(lk_states[0]);
             ++i)
        {
                if (lk_states[i].used &&
                    lk_states[i].fd == fd)
                        return &lk_states[i];
        }

        for (size_t i = 0;
             i < sizeof(lk_states) /
                 sizeof(lk_states[0]);
             ++i)
        {
                if (!lk_states[i].used)
                {
                        lk_states[i].used = true;
                        lk_states[i].fd = fd;
                        lk_states[i].nopts = 0;

                        return &lk_states[i];
                }
        }

        return NULL;
}

static int lk_get_socket_info(
        int fd,
        int* domain,
        int* type,
        int* protocol)
{
        return check_socket(
                fd,
                domain,
                type,
                protocol);
}

static void lk_initialize_real(void)
{
        if (!lk_real_bind)
        {
                lk_real_bind =
                        (bind_fn)dlsym(
                                RTLD_NEXT,
                                "bind");
        }

        if (!lk_real_connect)
        {
                lk_real_connect =
                        (connect_fn)dlsym(
                                RTLD_NEXT,
                                "connect");
        }

        if (!lk_real_sendto)
        {
                lk_real_sendto =
                        (sendto_fn)dlsym(
                                RTLD_NEXT,
                                "sendto");
        }

        if (!lk_real_sendmsg)
        {
                lk_real_sendmsg =
                        (sendmsg_fn)dlsym(
                                RTLD_NEXT,
                                "sendmsg");
        }

        if (!lk_real_sendmmsg)
        {
                lk_real_sendmmsg =
                        (sendmmsg_fn)dlsym(
                                RTLD_NEXT,
                                "sendmmsg");
        }

        if (!lk_real_setsockopt)
        {
                lk_real_setsockopt =
                        (setsockopt_fn)dlsym(
                                RTLD_NEXT,
                                "setsockopt");
        }
}

__attribute__((constructor))
static void lk_initialize(void)
{
        lk_initialize_real();

        const char* bind_map =
                getenv("LK_BIND_MAP");

        if (bind_map && *bind_map)
        {
                lk_parse_map(
                        bind_map,
                        &lk_bind_map);
        }

        const char* conn_map =
                getenv("LK_CONN_MAP");

        if (conn_map && *conn_map)
        {
                lk_parse_map(
                        conn_map,
                        &lk_conn_map);
        }
}

static bool lk_parse_port_range(
        const char* text,
        uint16_t* lo,
        uint16_t* hi,
        bool* wildcard)
{
        *wildcard = false;

        if (!strcmp(text, "*"))
        {
                *wildcard = true;
                *lo = 0;
                *hi = 65535;
                return true;
        }

        const char* dash =
                strchr(text, '-');

        if (!dash)
        {
                char* endptr;

                unsigned long v =
                        strtoul(
                                text,
                                &endptr,
                                10);

                if (*endptr || v > 65535)
                        return false;

                *lo = *hi =
                        (uint16_t)v;

                return true;
        }

        char left[32];
        char right[32];

        size_t llen =
                (size_t)(dash - text);

        memcpy(left, text, llen);
        left[llen] = 0;

        strlcpy(
                right,
                dash + 1,
                sizeof(right));

        char* endptr;

        unsigned long l =
                strtoul(
                        left,
                        &endptr,
                        10);

        if (*endptr || l > 65535)
                return false;

        unsigned long h =
                strtoul(
                        right,
                        &endptr,
                        10);

        if (*endptr || h > 65535)
                return false;

        *lo = (uint16_t)l;
        *hi = (uint16_t)h;

        return true;
}

static bool lk_parse_match(
        const char* token,
        struct lk_match* out)
{
        memset(out, 0, sizeof(*out));

        if (*token == '#')
        {
                out->negate = true;
                ++token;
        }

        if (!strcmp(token, "*"))
        {
                out->wildcard = true;
                return true;
        }

        char buffer[LK_MAX_TOKEN];

        strlcpy(
                buffer,
                token,
                sizeof(buffer));

        char* port_part = NULL;
        char* addr_part = buffer;

        if (buffer[0] == '[')
        {
                char* end =
                        strchr(buffer, ']');

                if (!end)
                        return false;

                *end = 0;

                addr_part =
                        buffer + 1;

                if (end[1] == ':')
                        port_part =
                                end + 2;
        }
        else
        {
                char* colon =
                        strrchr(buffer, ':');

                if (colon &&
                    !strchr(buffer, '/'))
                {
                        *colon = 0;
                        port_part =
                                colon + 1;
                }
        }

        char* slash =
                strchr(addr_part, '/');

        if (slash)
                *slash = 0;

        if (inet_pton(
                    AF_INET,
                    addr_part,
                    &out->addr.in) == 1)
        {
                out->family = AF_INET;

                out->prefix =
                        slash
                        ? atoi(slash + 1)
                        : 32;
        }
        else
        {
                char scoped[
                        INET6_ADDRSTRLEN +
                        IF_NAMESIZE + 2];

                strlcpy(
                        scoped,
                        addr_part,
                        sizeof(scoped));

                char* percent =
                        strchr(scoped, '%');

                if (percent)
                {
                        *percent = 0;

                        out->ifindex =
                                if_nametoindex(
                                        percent + 1);
                }

                if (inet_pton(
                            AF_INET6,
                            scoped,
                            &out->addr.in6) != 1)
                {
                        return false;
                }

                out->family = AF_INET6;

                out->prefix =
                        slash
                        ? atoi(slash + 1)
                        : 128;
        }

        if (port_part)
        {
                if (!lk_parse_port_range(
                            port_part,
                            &out->port_lo,
                            &out->port_hi,
                            &out->any_port))
                {
                        return false;
                }
        }
        else
        {
                out->any_port = true;
        }

        return true;
}

static bool lk_match_ipv4_prefix(
        const struct in_addr* a,
        const struct in_addr* b,
        uint8_t prefix)
{
        uint32_t aa =
                ntohl(a->s_addr);

        uint32_t bb =
                ntohl(b->s_addr);

        uint32_t mask =
                prefix == 0
                ? 0
                : (~0u << (32 - prefix));

        return
                (aa & mask) ==
                (bb & mask);
}

static bool lk_match_ipv6_prefix(
        const struct in6_addr* a,
        const struct in6_addr* b,
        uint8_t prefix)
{
        const uint8_t* aa =
                (const uint8_t*)a;

        const uint8_t* bb =
                (const uint8_t*)b;

        unsigned bits = prefix;

        for (unsigned i = 0;
             i < 16;
             ++i)
        {
                if (!bits)
                        return true;

                uint8_t mask =
                        bits >= 8
                        ? 0xff
                        : (0xff << (8 - bits));

                if ((aa[i] & mask) !=
                    (bb[i] & mask))
                {
                        return false;
                }

                bits =
                        bits > 8
                        ? bits - 8
                        : 0;
        }

        return true;
}

static bool lk_match_one(
        const struct lk_match* rule,
        const struct sockaddr* sa)
{
        if (sa->sa_family == AF_UNIX)
                return false;

        if (rule->wildcard)
        {
                return
                        sa->sa_family ==
                                AF_INET ||
                        sa->sa_family ==
                                AF_INET6;
        }

        uint16_t port = 0;

        if (sa->sa_family == AF_INET)
        {
                if (rule->family != AF_INET)
                        return false;

                const struct sockaddr_in* sin =
                        (const struct sockaddr_in*)sa;

                port =
                        ntohs(sin->sin_port);

                if (!lk_match_ipv4_prefix(
                                &sin->sin_addr,
                                &rule->addr.in,
                                rule->prefix))
                {
                        return false;
                }
        }
        else if (sa->sa_family == AF_INET6)
        {
                if (rule->family != AF_INET6)
                        return false;

                const struct sockaddr_in6* sin6 =
                        (const struct sockaddr_in6*)sa;

                port =
                        ntohs(sin6->sin6_port);

                if (rule->ifindex &&
                    sin6->sin6_scope_id !=
                        rule->ifindex)
                {
                        return false;
                }

                if (!lk_match_ipv6_prefix(
                                &sin6->sin6_addr,
                                &rule->addr.in6,
                                rule->prefix))
                {
                        return false;
                }
        }
        else
        {
                return false;
        }

        if (rule->any_port)
                return true;

        return
                port >= rule->port_lo &&
                port <= rule->port_hi;
}

static const char* lk_match_map(
        const struct lk_map* map,
        const struct sockaddr* sa,
        socklen_t salen)
{
        (void)salen;

        if (!map || !sa)
                return NULL;

        for (size_t i = 0;
             i < map->ngroups;
             ++i)
        {
                const struct lk_group* group =
                        &map->groups[i];

                for (size_t j = 0;
                     j < group->nmatches;
                     ++j)
                {
                        const struct lk_match* rule =
                                &group->matches[j];

                        if (!lk_match_one(rule, sa))
                                continue;

                        if (rule->negate)
                                return NULL;

                        return
                                group->socket_path;
                }
        }

        return NULL;
}

static void lk_track_sockopt(
        int fd,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen)
{
        if (!optval ||
            optlen <= 0 ||
            optlen > LK_MAX_OPTVAL)
        {
                return;
        }

        pthread_mutex_lock(
                &lk_state_lock);

        struct lk_socket_state* state =
                lk_get_socket_state(fd);

        if (!state)
        {
                pthread_mutex_unlock(
                        &lk_state_lock);
                return;
        }

        for (size_t i = 0;
             i < state->nopts;
             ++i)
        {
                struct lk_sockopt* opt =
                        &state->opts[i];

                if (opt->level == level &&
                    opt->optname == optname)
                {
                        memcpy(
                                opt->value,
                                optval,
                                optlen);

                        opt->optlen =
                                optlen;

                        pthread_mutex_unlock(
                                &lk_state_lock);

                        return;
                }
        }

        if (state->nopts >=
            LK_MAX_SOCKOPTS)
        {
                pthread_mutex_unlock(
                        &lk_state_lock);
                return;
        }

        struct lk_sockopt* opt =
                &state->opts[state->nopts++];

        opt->level = level;
        opt->optname = optname;
        opt->optlen = optlen;

        memcpy(
                opt->value,
                optval,
                optlen);

        pthread_mutex_unlock(
                &lk_state_lock);
}

static void lk_copy_socket_opts(
        int oldfd,
        int newfd)
{
        pthread_mutex_lock(
                &lk_state_lock);

        struct lk_socket_state* state =
                lk_get_socket_state(oldfd);

        if (!state)
        {
                pthread_mutex_unlock(
                        &lk_state_lock);
                return;
        }

        for (size_t i = 0;
             i < state->nopts;
             ++i)
        {
                struct lk_sockopt* opt =
                        &state->opts[i];

                lk_real_setsockopt(
                        newfd,
                        opt->level,
                        opt->optname,
                        opt->value,
                        opt->optlen);
        }

        pthread_mutex_unlock(
                &lk_state_lock);
}

static bool lk_redirect_socket(
        int fd,
        const char* server)
{
        int domain;
        int type;
        int protocol;

        if (lk_get_socket_info(
                    fd,
                    &domain,
                    &type,
                    &protocol) <= 0)
        {
                return false;
        }

        int flags =
                fcntl(fd, F_GETFL, 0);

        if (flags < 0)
                return false;

        if (flags & O_NONBLOCK)
                type |= SOCK_NONBLOCK;

        int fdflags =
                fcntl(fd, F_GETFD, 0);

        if (fdflags >= 0 &&
            (fdflags & FD_CLOEXEC))
        {
                type |= SOCK_CLOEXEC;
        }

        AUTO_CLOSE fd_t newfd =
                xsocket(
                        server,
                        domain,
                        type,
                        protocol);

        if (newfd < 0)
                return false;

        lk_copy_socket_opts(fd, newfd);

        if (!switcheroo(fd, newfd))
                return false;

        close_p(&newfd);

        return true;
}

static bool lk_parse_group(
        const char* text,
        struct lk_group* group)
{
        const char* space =
                strrchr(text, ' ');

        if (!space)
                return false;

        size_t matches_len =
                (size_t)(space - text);

        char matches[4096];

        memcpy(
                matches,
                text,
                matches_len);

        matches[matches_len] = 0;

        group->socket_path =
                strdup(space + 1);

        char* saveptr = NULL;

        for (char* tok =
                        strtok_r(
                                matches,
                                ",",
                                &saveptr);
             tok;
             tok =
                        strtok_r(
                                NULL,
                                ",",
                                &saveptr))
        {
                group->matches =
                        realloc(
                                group->matches,
                                (group->nmatches + 1) *
                                sizeof(
                                        struct lk_match));

                if (!lk_parse_match(
                            tok,
                            group->matches +
                                group->nmatches))
                {
                        return false;
                }

                ++group->nmatches;
        }

        return true;
}

static bool lk_parse_map(
        const char* text,
        struct lk_map* map)
{
        const char* p = text;

        while (*p)
        {
                while (*p == ' ' ||
                       *p == ',')
                {
                        ++p;
                }

                if (!*p)
                        break;

                if (*p != '(')
                        return false;

                ++p;

                const char* end =
                        strchr(p, ')');

                if (!end)
                        return false;

                size_t len =
                        (size_t)(end - p);

                char groupbuf[4096];

                memcpy(
                        groupbuf,
                        p,
                        len);

                groupbuf[len] = 0;

                map->groups =
                        realloc(
                                map->groups,
                                (map->ngroups + 1) *
                                sizeof(
                                        struct lk_group));

                struct lk_group* group =
                        map->groups +
                        map->ngroups;

                memset(
                        group,
                        0,
                        sizeof(*group));

                if (!lk_parse_group(
                            groupbuf,
                            group))
                {
                        return false;
                }

                ++map->ngroups;

                p = end + 1;
        }

        return true;
}

__attribute__((visibility("default"), weak))
int setsockopt(
        int sockfd,
        int level,
        int optname,
        const void* optval,
        socklen_t optlen)
{
        lk_initialize_real();

        int ret =
                lk_real_setsockopt(
                        sockfd,
                        level,
                        optname,
                        optval,
                        optlen);

        if (ret == 0)
        {
                lk_track_sockopt(
                        sockfd,
                        level,
                        optname,
                        optval,
                        optlen);
        }

        return ret;
}

__attribute__((visibility("default")))
int bind(
        int sockfd,
        const struct sockaddr* address,
        socklen_t addrlen)
{
        lk_initialize_real();

        const char* server =
                lk_match_map(
                        &lk_bind_map,
                        address,
                        addrlen);

        if (server)
        {
                if (!lk_redirect_socket(
                            sockfd,
                            server))
                {
                        return -1;
                }
        }

        return lk_real_bind(
                sockfd,
                address,
                addrlen);
}

__attribute__((visibility("default")))
int connect(
        int sockfd,
        const struct sockaddr* address,
        socklen_t addrlen)
{
        lk_initialize_real();

        const char* server =
                lk_match_map(
                        &lk_conn_map,
                        address,
                        addrlen);

        if (server)
        {
                if (!lk_redirect_socket(
                            sockfd,
                            server))
                {
                        return -1;
                }
        }

        return lk_real_connect(
                sockfd,
                address,
                addrlen);
}

__attribute__((visibility("default")))
ssize_t sendto(
        int sockfd,
        const void* buffer,
        size_t length,
        int flags,
        const struct sockaddr* dest_addr,
        socklen_t addrlen)
{
        lk_initialize_real();

        if (dest_addr)
        {
                const char* server =
                        lk_match_map(
                                &lk_conn_map,
                                dest_addr,
                                addrlen);

                if (server)
                {
                        if (!lk_redirect_socket(
                                    sockfd,
                                    server))
                        {
                                return -1;
                        }
                }
        }

        return lk_real_sendto(
                sockfd,
                buffer,
                length,
                flags,
                dest_addr,
                addrlen);
}

__attribute__((visibility("default")))
ssize_t sendmsg(
        int sockfd,
        const struct msghdr* msg,
        int flags)
{
        lk_initialize_real();

        if (msg && msg->msg_name)
        {
                const char* server =
                        lk_match_map(
                                &lk_conn_map,
                                (const struct sockaddr*)
                                        msg->msg_name,
                                msg->msg_namelen);

                if (server)
                {
                        if (!lk_redirect_socket(
                                    sockfd,
                                    server))
                        {
                                return -1;
                        }
                }
        }

        return lk_real_sendmsg(
                sockfd,
                msg,
                flags);
}

__attribute__((visibility("default")))
int sendmmsg(
        int sockfd,
        struct mmsghdr* vec,
        unsigned int vlen,
        int flags)
{
        lk_initialize_real();

        for (unsigned int i = 0;
             i < vlen;
             ++i)
        {
                struct msghdr* msg =
                        &vec[i].msg_hdr;

                if (!msg->msg_name)
                        continue;

                const char* server =
                        lk_match_map(
                                &lk_conn_map,
                                (const struct sockaddr*)
                                        msg->msg_name,
                                msg->msg_namelen);

                if (!server)
                        continue;

                if (!lk_redirect_socket(
                            sockfd,
                            server))
                {
                        return -1;
                }

                break;
        }

        return lk_real_sendmmsg(
                sockfd,
                vec,
                vlen,
                flags);
}
