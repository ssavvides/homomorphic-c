#ifndef TIME_H
#define TIME_H

unsigned long time_micros();

double time_millis();

void print_micros(const char *message, const double micros);

void print_millis(const char *message, const double millis);

void get_stats(double* mean, double* std, unsigned long *micros, int size);
void print_stats(unsigned long *times, int size);

#endif
