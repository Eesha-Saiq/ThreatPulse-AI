
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <omp.h>
#include <vector>

using namespace std;

double calculate_score(double x) {
    return sqrt(x + 1.0) * log(x + 2.0) + sin(x);
}

int main() {
    const long long N = 5'000'000;
    vector<double> input(N), sequential(N), parallel(N);

    for (long long i = 0; i < N; ++i) {
        input[i] = static_cast<double>((i % 10000) + 1);
    }

    // 1. Sequential execution
    double start = omp_get_wtime();

    for (long long i = 0; i < N; ++i) {
        sequential[i] = calculate_score(input[i]);
    }

    double sequential_time = omp_get_wtime() - start;

    // 2. OpenMP parallel execution
    start = omp_get_wtime();

    #pragma omp parallel for schedule(static)
    for (long long i = 0; i < N; ++i) {
        parallel[i] = calculate_score(input[i]);
    }

    double parallel_time = omp_get_wtime() - start;

    // 3. Verify correctness
    bool correct = true;
    for (long long i = 0; i < N; ++i) {
        if (abs(sequential[i] - parallel[i]) > 1e-12) {
            correct = false;
            break;
        }
    }

    int threads = omp_get_max_threads();
    double speedup = sequential_time / parallel_time;
    double efficiency = speedup / threads * 100.0;

    cout << fixed << setprecision(6);
    cout << "\n===== ThreatPulse PDC Benchmark =====\n";
    cout << "Workload size       : " << N << '\n';
    cout << "OpenMP max threads  : " << threads << '\n';
    cout << "Sequential time     : " << sequential_time << " seconds\n";
    cout << "OpenMP time         : " << parallel_time << " seconds\n";
    cout << "Speedup             : " << speedup << "x\n";
    cout << "Parallel efficiency : " << efficiency << "%\n";
    cout << "Results match       : " << (correct ? "YES" : "NO") << '\n';

    return correct ? 0 : 1;
}
