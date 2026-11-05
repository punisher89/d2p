/* Разбор ServerHelloDone в TLS 1.2: сообщения через границы записей. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "d2k_detect.h"

int d2k_resp_handshake12(const char *host, const char *port, const char *sni,
                         const d2k_opts *opt);
void d2k_resp_decide(int target, int control, int unmeasured, int repeats,
                     d2k_resp_result *res);

int d2k_resp_scan12(const uint8_t *buf, size_t have, int *done);

static size_t rec(uint8_t *o, uint8_t type, const uint8_t *p, size_t n)
{
    o[0] = type; o[1] = 3; o[2] = 3; o[3] = (uint8_t)(n >> 8); o[4] = (uint8_t)n;
    memcpy(o + 5, p, n);
    return 5 + n;
}

static uint8_t stream[40000], out[50000];

int main(void)
{
    size_t n = 0, o = 0, certlen = 20000;
    int done, fails = 0, r;

    /* ServerHello(4+10) | Certificate 20000 | ServerHelloDone */
    stream[n++] = 2; stream[n++] = 0; stream[n++] = 0; stream[n++] = 10; n += 10;
    stream[n++] = 11; stream[n++] = 0; stream[n++] = (uint8_t)(certlen >> 8);
    stream[n++] = (uint8_t)certlen;
    memset(stream + n, 0xab, certlen); n += certlen;
    stream[n++] = 14; stream[n++] = 0; stream[n++] = 0; stream[n++] = 0;
    o += rec(out + o, 22, stream, 16384);
    o += rec(out + o, 22, stream + 16384, n - 16384);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 1 || !done) { printf("FAIL split cert: r=%d done=%d\n", r, done); fails++; }

    /* 0e 00 00 00 внутри тела Certificate на границе записей — не конец */
    memset(stream, 0xab, sizeof(stream)); n = 0;
    stream[n++] = 11; stream[n++] = 0; stream[n++] = (uint8_t)(certlen >> 8);
    stream[n++] = (uint8_t)certlen;
    memset(stream + n, 0xab, certlen);
    stream[4 + 16380 - 4] = 0x0e; stream[4 + 16380 - 3] = 0; stream[4 + 16380 - 2] = 0; stream[4 + 16380 - 1] = 0;
    n += certlen; o = 0;
    o += rec(out + o, 22, stream, 16384);
    o += rec(out + o, 22, stream + 16384, n - 16384);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 0 || done) { printf("FAIL embedded 0e: r=%d done=%d\n", r, done); fails++; }

    /* заголовок сообщения разорван между записями: 0e | 00 00 00 */
    o = 0;
    o += rec(out + o, 22, (const uint8_t *)"\x0e", 1);
    o += rec(out + o, 22, (const uint8_t *)"\x00\x00\x00", 3);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 1 || !done) { printf("FAIL split header: r=%d done=%d\n", r, done); fails++; }

    /* 0e 00 00 00 в НАЧАЛЕ второй записи — тело Certificate, не ServerHelloDone */
    memset(stream, 0xab, sizeof(stream)); n = 0;
    stream[n++] = 11; stream[n++] = 0; stream[n++] = (uint8_t)(certlen >> 8);
    stream[n++] = (uint8_t)certlen;
    memset(stream + n, 0xab, certlen);
    stream[16384] = 0x0e; stream[16385] = 0; stream[16386] = 0; stream[16387] = 0;
    n += certlen; o = 0;
    o += rec(out + o, 22, stream, 16384);
    o += rec(out + o, 22, stream + 16384, n - 16384);
    r = d2k_resp_scan12(out, o, &done);
    if (r != 0 || done) { printf("FAIL 0e at record start: r=%d done=%d\n", r, done); fails++; }

    /* Решение: BLOCKED требует единогласного контроля; полный проход
       цели доказывает CLEAR даже если отдельный контроль не удался. */
    {
        d2k_resp_result res;
        memset(&res, 0, sizeof(res));
        d2k_resp_decide(0, 3, 1, 3, &res);
        if (res.verdict != D2K_RESP_NOT_APPLICABLE) { printf("FAIL decide unmeasured\n"); fails++; }
        d2k_resp_decide(0, 3, 0, 3, &res);
        if (res.verdict != D2K_RESP_BLOCKED) { printf("FAIL decide blocked\n"); fails++; }
        d2k_resp_decide(3, 0, 0, 3, &res);
        if (res.verdict != D2K_RESP_CLEAR) { printf("FAIL target all pass must be clear\n"); fails++; }
        d2k_resp_decide(0, 1, 0, 3, &res);
        if (res.verdict != D2K_RESP_FLAKY) { printf("FAIL partial control must be flaky\n"); fails++; }
        d2k_resp_decide(0, 2, 0, 3, &res);
        if (res.verdict != D2K_RESP_FLAKY) { printf("FAIL 2/3 control must be flaky\n"); fails++; }
        d2k_resp_decide(1, 3, 0, 3, &res);
        if (res.verdict != D2K_RESP_FLAKY) { printf("FAIL partial target must be flaky\n"); fails++; }
        d2k_resp_decide(3, 0, 3, 3, &res);
        if (res.verdict != D2K_RESP_CLEAR) { printf("FAIL target clear despite control unmeasured\n"); fails++; }
    }

    /* живой пир: шлёт >64 КБ записей без ServerHelloDone -> -1, не 0 */
    {
        int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        char port[16];
        pid_t pid;
        d2k_opts opt;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(ls, (struct sockaddr *)&a, sizeof(a)) || listen(ls, 1) ||
            getsockname(ls, (struct sockaddr *)&a, &al)) { printf("FAIL listen\n"); return 1; }
        snprintf(port, sizeof(port), "%d", ntohs(a.sin_port));
        pid = fork();
        if (pid == 0) {
            uint8_t junk[16384], rb[16389], tmp[2048];
            int c = accept(ls, NULL, NULL), k;
            memset(junk, 0xab, sizeof(junk));
            (void)!read(c, tmp, sizeof(tmp));
            rec(rb, 22, junk, sizeof(junk));
            for (k = 0; k < 6; k++) { if (write(c, rb, sizeof(rb)) <= 0) break; }
            sleep(1);
            _exit(0);
        }
        memset(&opt, 0, sizeof(opt));
        opt.timeout_ms = 2000;
        opt.repeats = 1;
        opt.allow_loopback = 1;
        r = d2k_resp_handshake12("127.0.0.1", port, "example.org", &opt);
        if (r != -1) { printf("FAIL overflow handshake12=%d\n", r); fails++; }
        waitpid(pid, NULL, 0);
        close(ls);
    }

    if (fails) return 1;
    printf("test_response: ok\n");
    return 0;
}
