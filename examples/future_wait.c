#include <except.h>

/* Plain C89 version of https://cplusplus.com/reference/future/future/wait/

// future::wait
#include <iostream>       // std::cout
#include <future>         // std::async, std::future
#include <chrono>         // std::chrono::milliseconds

// a non-optimized way of checking for prime numbers:
bool is_prime (int x) {
  for (int i=2; i<x; ++i) if (x%i==0) return false;
  return true;
}

int main ()
{
  // call function asynchronously:
  std::future<bool> fut = std::async (is_prime,194232491);

  std::cout << "checking...\n";
  fut.wait();

  std::cout << "\n194232491 ";
  if (fut.get())      // guaranteed to be ready (and not block) after wait returns
    std::cout << "is prime.\n";
  else
    std::cout << "is not prime.\n";

  return 0;
}
*/

// a non-optimized way of checking for prime numbers:
void *is_prime(param_t arg) {
    int i, x = arg->integer;
    for (i = 2; i < x; ++i) if (x % i == 0) return $(false);
    return $(true);
}

int prime(uint32_t argc, void *argv) {
    if (argc > 0) {
        // call function asynchronously:
        future_t fut = thrd_async(is_prime, 1, argv);

        cout("checking...\n");
		thrd_wait(fut, yield_active_info);

		cout("\n194232491 ");
		if (thrd_get(fut).boolean) // guaranteed to be ready (and not block) after `thrd_wait` returns
			cout("is prime.\n");
        else
			cout("is not prime.\n");
    }

    return 0;
}

void main_main(param_t na) {
	prime(1, casting(194232491));
}

int main(int argc, char **argv) {
	events_init(1024);
	events_t *loop = events_create(1);
	async_ex(Kb(64), main_main, 0);
	async_run(loop);
	events_destroy(loop);

	return 0;
}