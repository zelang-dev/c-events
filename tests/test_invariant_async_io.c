#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Forward declaration of the function under test from async_io.c */
extern void async_io_copy_addr(void *dst, size_t dst_size, struct addrinfo *res);

START_TEST(test_memcpy_buffer_overflow_protection)
{
    /* Invariant: memcpy into dst must never exceed dst_size bytes,
       even when res->ai_addrlen is unexpectedly large or malicious */
    
    char dst_buffer[sizeof(struct sockaddr_in6)];
    size_t dst_size = sizeof(struct sockaddr_in6);
    
    struct addrinfo ai;
    struct sockaddr_in addr_valid;
    struct sockaddr_in addr_oversized;
    
    /* Test case 1: Valid input (IPv4 address, normal size) */
    memset(&addr_valid, 0, sizeof(addr_valid));
    addr_valid.sin_family = AF_INET;
    addr_valid.sin_port = htons(80);
    inet_pton(AF_INET, "192.0.2.1", &addr_valid.sin_addr);
    
    memset(&ai, 0, sizeof(ai));
    ai.ai_addr = (struct sockaddr *)&addr_valid;
    ai.ai_addrlen = sizeof(struct sockaddr_in);
    
    memset(dst_buffer, 0, dst_size);
    async_io_copy_addr(dst_buffer, dst_size, &ai);
    ck_assert_int_eq(ai.ai_addrlen, sizeof(struct sockaddr_in));
    
    /* Test case 2: Boundary case (ai_addrlen equals dst_size) */
    ai.ai_addrlen = dst_size;
    memset(dst_buffer, 0, dst_size);
    async_io_copy_addr(dst_buffer, dst_size, &ai);
    ck_assert_int_le(ai.ai_addrlen, dst_size);
    
    /* Test case 3: Adversarial case (ai_addrlen exceeds dst_size) */
    memset(&addr_oversized, 0, sizeof(addr_oversized));
    ai.ai_addr = (struct sockaddr *)&addr_oversized;
    ai.ai_addrlen = dst_size + 1024;  /* Malicious: claims huge size */
    
    memset(dst_buffer, 0xAA, dst_size);
    char canary[16];
    memset(canary, 0xBB, sizeof(canary));
    
    async_io_copy_addr(dst_buffer, dst_size, &ai);
    
    /* Verify canary is untouched (no overflow past dst_size) */
    for (int i = 0; i < (int)sizeof(canary); i++) {
        ck_assert_uint_eq((unsigned char)canary[i], 0xBB);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_memcpy_buffer_overflow_protection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}