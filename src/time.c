#include <sys/time.h>
#include <stdio.h>
#include <math.h>

#include "time.h"

unsigned long time_micros() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000000 + tv.tv_usec;
}

double time_millis() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
}

void print_micros(const char *message, const double micros) {
    printf("%s: %.2f us\n", message, micros);
}

void print_millis(const char *message, const double millis) {
    printf("%s: %.2f ms\n", message, millis);
}

// NB: takes micros as input but prints in millis
void print_stats(unsigned long *micros, int size) {

    double sum = 0;
    for (int i = 0; i < size; i++)
        sum += ((double) micros[i] / 1000);

    double mean = sum / size;

    double variance = 0;
    for (int i = 0; i < size; i++)
        variance += pow((double) micros[i] / 1000 - mean, 2);
    variance /= size;

    double std = sqrt(variance);

    //print_millis("sum", sum);
    print_millis("mean", mean);
    //print_millis("variance", variance);
    print_millis("std", std);
}
