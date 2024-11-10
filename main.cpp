#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <windows.h>

template<class... Args>
void log(Args... args) {
    std::stringstream oss;
    (oss << ... << args);
    std::cout << oss.str() << std::endl;
}

__forceinline void **AddressOfReturnAddress_() {
    void **ret_address;
    asm volatile ("lea 8(%%rbp), %0\n":"=r"(ret_address));
    return ret_address;
}

void WINAPI MySleep(DWORD dwMilliseconds) {
    //
    // Locate this stack frame's return address.
    // 
    void **overwrite = AddressOfReturnAddress_();
    void * origReturnAddress = *overwrite;

    log("[>] Original return address: ", 
        std::hex, *overwrite, 
        ". Finishing call stack...");

    //
    // By overwriting the return address with 0 we're basically telling call stack unwinding algorithm
    // to stop unwinding call stack any further, as there further frames. This we can hide our remaining stack frames
    // referencing shellcode memory allocation from residing on a call stack.
    //
    *overwrite = 0;

    log("\n===> MySleep(", std::dec, dwMilliseconds, ")\n");

    //
    // Perform sleep emulating originally hooked functionality.
    //
    ::SleepEx(dwMilliseconds, false);

    //
    // Restore original thread's call stack.
    //
    log("[<] Restoring original return address...");
    *overwrite = origReturnAddress;
}

int main() {
    while (1)
        MySleep(5000);
    return 0;
}
