#include <events.h>

void main_main(param_t args) {
	const char *name = events_hostname();

	/* Generate the key. */
	puts("Generating RSA key..."CLR_LN);
	EVP_PKEY *pkey = rsa_pkey(4096);
	if (!pkey)
		panicking("Failed!"CLR_LN);

	defer(EVP_PKEY_free, pkey);
	/* Generate the certificate. */
	puts("Generating x509 certificate..."CLR_LN);
	X509 *x509 = x509_self(pkey, NULL, NULL, name);
	if (!x509)
		panicking("Failed!"CLR_LN);

	defer(X509_free, x509);
	/* Write the private key and certificate out to disk. */
	puts("Writing key and certificate to disk..."CLR_LN);
	if (x509_pkey_write(pkey, x509)) {
		puts("Success!"CLR_LN);
		return;
	}

	panicking("Failed!"CLR_LN);
}


int main(int argc, char **argv) {
	return events_start(1024, main_main, 0);
}
