#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile uintptr_t sink_value;

__attribute__((noinline, used, visibility("default")))
void tlskh_probe(
    void *a0, void *a1, void *a2, void *a3, void *a4, void *a5,
    void *a6, void *a7, void *a8, void *a9, void *a10, void *a11
) {
    void *args[12] = {a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11};
    for (int i = 0; i < 12; i++) {
        sink_value ^= (uintptr_t)args[i];
    }
}

static void fill_bytes(uint8_t *buffer, int seed) {
    for (int i = 0; i < 32; i++) {
        buffer[i] = (uint8_t)((i * 73 + seed * 29 + 17) & 0xff);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s TRUE_INDEX\n", argv[0]);
        return 2;
    }
    int true_index = atoi(argv[1]);
    if (true_index < 0 || true_index > 11) {
        return 2;
    }
    uint8_t buffers[12][32];
    void *args[12];
    for (int call = 1; call <= 10; call++) {
        for (int index = 0; index < 12; index++) {
            if (call == 1 && index != true_index) {
                memset(buffers[index], 0, sizeof(buffers[index]));
            } else {
                fill_bytes(buffers[index], true_index * 31 + index + call);
            }
            args[index] = buffers[index];
        }
        int invalid_index = (true_index + 1) % 12;
        args[invalid_index] = (void *)(uintptr_t)1;
        tlskh_probe(
            args[0], args[1], args[2], args[3], args[4], args[5],
            args[6], args[7], args[8], args[9], args[10], args[11]
        );
        usleep(20000);
    }
    return sink_value == UINTPTR_MAX ? 1 : 0;
}
