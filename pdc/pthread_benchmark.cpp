#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <pthread.h>
#include <vector>

using namespace std;

using Clock = chrono::steady_clock;

double calculate_score(double x) {
    return sqrt(x + 1.0) * log(x + 2.0) + sin(x);
}

struct ThreadData {
    const vector<double>* input;
    vector<double>* output;
    long long start;
    long long end;
};

void* calculate_chunk(void* argument) {
    ThreadData* data = static_cast<ThreadData*>(argument);

    for (long long i = data->start; i < data->end; ++i) {
        (*data->output)[i] = calculate_score((*data->input)[i]);
    }

    return nullptr;
}

int main() {
    const long long N = 5'000'000;
    const int thread_count = 4;

    vector<double> input(N), sequential(N), parallel(N);

    for (long long i = 0; i < N; ++i) {
        input[i] = static_cast<double>((i % 10000) + 1);
    }

    auto start = Clock::now();

    for (long long i = 0; i < N; ++i) {
        sequential[i] = calculate_score(input[i]);
    }

    double sequential_time =
        chrono::duration<double>(Clock::now() - start).count();

    pthread_t threads[thread_count];
    ThreadData data[thread_count];

    start = Clock::now();

    long long chunk_size = (N + thread_count - 1) / thread_count;
    int created = 0;

    for (int t = 0; t < thread_count; ++t) {
        data[t] = {
            &input,
            &parallel,
            t * chunk_size,
            min(N, (t + 1LL) * chunk_size)
        };

        if (pthread_create(&threads[t], nullptr,
                           calculate_chunk, &data[t]) != 0) {
            cerr << "Failed to create thread " << t << '\n';
            for (int j = 0; j < created; ++j) {
                pthread_join(threads[j], nullptr);
            }
            return 1;
        }

        ++created;
    }

    for (int t = 0; t < created; ++t) {
        if (pthread_join(threads[t], nullptr) != 0) {
            cerr << "Failed to join thread " << t << '\n';
            return 1;
        }
    }

    double parallel_time =
        chrono::duration<double>(Clock::now() - start).count();

    bool correct = true;

    for (long long i = 0; i < N; ++i) {
        if (abs(sequential[i] - parallel[i]) > 1e-12) {
            correct = false;
            break;
        }
    }

    cout << fixed << setprecision(6);
    cout << "\n===== ThreatPulse Pthreads Benchmark =====\n";
    cout << "Workload size       : " << N << '\n';
    cout << "POSIX threads       : " << thread_count << '\n';
    cout << "Sequential time     : " << sequential_time << " seconds\n";
    cout << "Pthreads time       : " << parallel_time << " seconds\n";
    cout << "Speedup             : "
         << sequential_time / parallel_time << "x\n";
    cout << "Parallel efficiency : "
         << (sequential_time / parallel_time) / thread_count * 100.0
         << "%\n";
    cout << "Results match       : " << (correct ? "YES" : "NO") << '\n';

    return correct ? 0 : 1;
}
