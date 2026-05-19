#include "../test_assert.h"
#include <openssl/md5.h>

#if defined(_WIN32)
#   define TESTDIR "../../httpi/tests/httpi"
#else
#   define TESTDIR "../httpi/tests/httpi"
#endif

void check_func(int condition, string_t cond_txt, unsigned line);

static int s_total_tests = 0;
static int s_failed_tests = 0;

void check_func(int condition, string_t cond_txt, unsigned line)
{
	++s_total_tests;
	if (!condition) {
		printf("Fail on line %d: [%s]\n", line, cond_txt);
		++s_failed_tests;
	}
}

#define ASSERT(expr)                                                           \
	do {                                                                       \
		check_func(expr, #expr, __LINE__);                                     \
	} while (0)

#define REQUIRE(expr)                                                          \
	do {                                                                       \
		check_func(expr, #expr, __LINE__);                                     \
		if (!(expr)) {                                                         \
			exit(EXIT_FAILURE);                                                \
		}                                                                      \
	} while (0)

#define HTTP_PORT "8080"
#ifdef NO_SSL
#define HTTPS_PORT HTTP_PORT
#define LISTENING_ADDR "127.0.0.1:" HTTP_PORT
#else
#define HTTP_REDIRECT_PORT "8088"
#define HTTPS_PORT "8443"
#define LISTENING_ADDR                                                         \
	"127.0.0.1:" HTTP_PORT ",127.0.0.1:" HTTP_REDIRECT_PORT "r"                \
	",127.0.0.1:" HTTPS_PORT "s"
#endif

static char *read_file(string_t path, int *size) {
	FILE *fp;
	struct stat st;
	char *data = NULL;
	if ((fp = fs_fopen(path, "rb")) != NULL && !fs_fstat(fileno(fp), &st)) {
		*size = (int)st.st_size;
		data = malloc(*size);
		ASSERT(data != NULL);
		ASSERT(fs_fread(data, 1, *size, fp) == (size_t)*size);
		fs_fclose(fp);
	}
	return data;
}

static long fetch_data_size = 1024 * 1024;
static char *fetch_data;
static string_t inmemory_file_data = "hi there";
static string_t upload_filename = "upload_test.txt";
static string_t upload_filename2 = "upload_test2.txt";
static string_t upload_ok_message = "upload successful";

static string_t open_file_cb(http_t *conn, string_t path, size_t *size) {
	(void)conn;
	if (!strcmp(path, "./blah")) {
		*size = strlen(inmemory_file_data);
		return inmemory_file_data;
	}
	return NULL;
}

static void upload_cb(http_t *conn, string_t path) {
	char *p1, *p2;
	int len1, len2;

	if (atoi(http_get_query(conn)) == 1) {
		ASSERT(!strcmp(path, "./upload_test.txt"));
		ASSERT((p1 = read_file("../src/app/url.c", &len1)) != NULL);
		ASSERT((p2 = read_file(path, &len2)) != NULL);
		ASSERT(len1 == len2);
		ASSERT(memcmp(p1, p2, len1) == 0);
		free(p1);
		free(p2);
		remove(upload_filename);
	} else if (atoi(http_get_query(conn)) == 2) {
		if (!strcmp(path, "./upload_test.txt")) {
			ASSERT((p1 = read_file("include/httpi.h", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			free(p1);
			free(p2);
			remove(upload_filename);
		} else if (!strcmp(path, "./upload_test2.txt")) {
			ASSERT((p1 = read_file("README.md", &len1)) != NULL);
			ASSERT((p2 = read_file(path, &len2)) != NULL);
			ASSERT(len1 == len2);
			ASSERT(memcmp(p1, p2, len1) == 0);
			free(p1);
			free(p2);
			remove(upload_filename);
		} else {
			ASSERT(0);
		}
	} else {
		ASSERT(0);
	}

	http_printf(conn, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", (int)strlen(upload_ok_message), upload_ok_message);
}

static int begin_request_handler_cb(http_t *conn) {
	int req_len = (int)(http_get_length(conn));
	string_t s_req_len = http_get_header(conn, "Content-Length");
	char *data;
	long to_write, write_now;
	int bytes_read, bytes_written;

	ASSERT(((req_len == -1) && (s_req_len == NULL)) ||
	       ((s_req_len != NULL) && (req_len = atol(s_req_len))));

	if (!strncmp(http_get_uri(conn), "/data/", 6)) {
		if (!strcmp(http_get_uri(conn) + 6, "all")) {
			to_write = fetch_data_size;
		} else {
			to_write = atol(http_get_url(conn) + 6);
		}
		http_printf(conn,
		          "HTTP/1.1 200 OK\r\n"
		          "Connection: close\r\n"
		          "Content-Length: %li\r\n"
		          "Content-Type: text/plain\r\n\r\n",
		          to_write);
		while (to_write > 0) {
			write_now = to_write > fetch_data_size ? fetch_data_size : to_write;
			bytes_written = http_write(conn, fetch_data, write_now);
			ASSERT(bytes_written == write_now);
			if (bytes_written < 0) {
				ASSERT(0);
				break;
			}
			to_write -= bytes_written;
		}
		http_close_connection(conn);
		return 1;
	}

	if (!strcmp(http_get_url(conn), "/content_length")) {
		if (req_len > 0) {
			data = malloc(req_len);
			assert(data != NULL);
			bytes_read = http_read(conn, data, req_len);
			ASSERT(bytes_read == req_len);

			http_printf(conn,
			          "HTTP/1.1 200 OK\r\n"
			          "Connection: close\r\n"
			          "Content-Length: %d\r\n" /* The official definition */
			          "Content-Type: text/plain\r\n\r\n",
			          bytes_read);
			http_write(conn, data, bytes_read);
			free(data);
		} else {
			data = malloc(1024);
			assert(data != NULL);
			bytes_read = http_read(conn, data, 1024);

			http_printf(conn,
			          "HTTP/1.1 200 OK\r\n"
			          "Connection: close\r\n"
			          "Content-Type: text/plain\r\n\r\n");
			http_write(conn, data, bytes_read);

			free(data);
		}
		http_close_connection(conn);
		return 1;
	}

	if (!strcmp(http_get_url(conn), "/upload")) {
		ASSERT(http_get_query(conn) != NULL);
		ASSERT(http_upload(conn, ".") == atoi(http_get_query(conn)));
	}

	return 0;
}

static int log_message_cb(const http_t *conn, string_t msg) {
	(void)conn;
	printf("%s\n", msg);
	return 0;
}

static string_t OPTIONS[] = {
    "document_root",
    ".",
    "listening_ports",
    LISTENING_ADDR,
    "enable_keep_alive",
    "yes",
#ifndef NO_SSL
    /*"ssl_certificate",
    "../resources/ssl_cert.pem",*/
#endif
    NULL,
};

static char *read_conn(http_t *conn, int *size) {
	char buf[100], *data = NULL;
	int len;
	*size = 0;
	while ((len = http_read(conn, buf, sizeof(buf))) > 0) {
		*size += len;
		data = realloc(data, *size);
		ASSERT(data != NULL);
		memcpy(data + *size - len, buf, len);
	}
	return data;
}

void main_main(http_ini_t *ctx) {
	http_t *conn;
	static string_t boundary = "OOO___MY_BOUNDARY___OOO";
	char ebuf[100], buf[20], *file2_data;
	int file2_len;
	char *file_data, *post_data;
	int file_len, post_data_len;

	/* Upload one file */
	ASSERT((file_data = read_file("test-httpi_start.c", &file_len)) != NULL);
	post_data = NULL;
	post_data_len = alloc_printf(&post_data,
		NULL,
		0,
		"--%s\r\n"
		"Content-Disposition: form-data; "
		"name=\"file\"; "
		"filename=\"%s\"\r\n\r\n"
		"%.*s\r\n"
		"--%s--\r\n",
		boundary,
		upload_filename,
		file_len,
		file_data,
		boundary);
	ASSERT(post_data_len > 0);

	/* TODO (bel): ... */
	ASSERT((conn = http_download("localhost", atoi(HTTPS_PORT), 1,
		ebuf, sizeof(ebuf),
		"POST /upload?1 HTTP/1.1\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: multipart/form-data; "
		"boundary=%s\r\n\r\n"
		"%.*s", post_data_len, boundary,
		post_data_len, post_data)) != NULL);
	free(file_data), free(post_data);
	ASSERT(http_read(conn, buf, sizeof(buf)) == (int)strlen(upload_ok_message));
	ASSERT(memcmp(buf, upload_ok_message, strlen(upload_ok_message)) == 0);
	http_close_connection(conn);

	/* Upload two files */
	ASSERT((file_data = read_file("include/httpi.h", &file_len)) != NULL);
	ASSERT((file2_data = read_file("README.md", &file2_len)) != NULL);
	post_data = NULL;
	post_data_len = alloc_printf(&post_data, null, 0,
		/* First file */
		"--%s\r\n"
		"Content-Disposition: form-data; "
		"name=\"file\"; "
		"filename=\"%s\"\r\n\r\n"
		"%.*s\r\n"

		/* Second file */
		"--%s\r\n"
		"Content-Disposition: form-data; "
		"name=\"file\"; "
		"filename=\"%s\"\r\n\r\n"
		"%.*s\r\n"

		/* Final boundary */
		"--%s--\r\n",
		boundary, upload_filename,
		file_len, file_data,
		boundary, upload_filename2,
		file2_len, file2_data,
		boundary);
	ASSERT(post_data_len > 0);
	ASSERT((conn = http_download("localhost", atoi(HTTPS_PORT), 1,
		ebuf, sizeof(ebuf),
		"POST /upload?2 HTTP/1.1\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: multipart/form-data; "
		"boundary=%s\r\n\r\n"
		"%.*s", post_data_len, boundary,
		post_data_len, post_data)) != NULL);
	free(file_data), free(file2_data), free(post_data);
	ASSERT(http_read(conn, buf, sizeof(buf)) == (int)strlen(upload_ok_message));
	ASSERT(memcmp(buf, upload_ok_message, strlen(upload_ok_message)) == 0);
	http_close_connection(conn);

	/* Stop the server */
	http_stop(ctx);
}

TEST(http_upload) {
	http_ini_t *ctx;
	http_clb_t cb = http_callbacks(begin_request_handler_cb, log_message_cb, NULL, open_file_cb, NULL, upload_cb);

	/* Initialize the library */
	ASSERT_TRUE(is_type(ctx = httpi_setup(0, &cb, null, server_opts(OPTIONS)), DATA_INFO_SERVER));

	/* Start the server */
	httpi_start(ctx, main_main);
	return 0;
}

TEST(list) {
	char buffer[512];
	int i, unused, result = 0;

	/* create test data */
	fetch_data = (char *)malloc(fetch_data_size);
	for (i = 0; i < fetch_data_size; i++) {
		fetch_data[i] = 'a' + i % 10;
	}

#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif
	unused = chdir(TESTDIR);

	/* print headline */
	cout("HttPi %s upload test\n\n", httpi_version());
	getcwd(buffer, sizeof(buffer));
	cout("Test directory is \"%s\"\n", buffer); /* should be the "test" directory */

	FILE *f = fopen("hello.txt", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain hello.txt\n");
	}

	f = fopen("test-http_route.c", "r");
	if (f) {
		fclose(f);
	} else {
		cout("Error: Test directory does not contain test-http_route.c\n");
	}

	EXEC_TEST(http_upload);

	unused = chdir("../build");
#if defined(_WIN32) || defined(_WIN64)
	unused = chdir("Debug");
#endif

	/* test completed */
	free(fetch_data);

	return result;
}

int main(int argc, char **argv) {
	TEST_FUNC(list());
}
