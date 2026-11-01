
#include <mpi.h>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

double calculate_score(double x) {
    return sqrt(x + 1.0) * log(x + 2.0) + sin(x);
}

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    const long long N = 5000000;
    long long chunk = N / size;
    long long start_index = rank * chunk;
    long long end_index = (rank == size - 1) ? N : start_index + chunk;

    double local_sum = 0.0;
    double global_sum = 0.0;

    MPI_Barrier(MPI_COMM_WORLD);
    double start_time = MPI_Wtime();

    for (long long i = start_index; i < end_index; ++i) {
        double x = static_cast<double>((i % 10000) + 1);
        local_sum += calculate_score(x);
    }

    MPI_Reduce(
        &local_sum, &global_sum, 1,
        MPI_DOUBLE, MPI_SUM, 0, MPI_COMM_WORLD
    );

    MPI_Barrier(MPI_COMM_WORLD);
    double local_elapsed = MPI_Wtime() - start_time;
    double max_elapsed = 0.0;

    MPI_Reduce(
        &local_elapsed, &max_elapsed, 1,
        MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD
    );

    if (rank == 0) {
        double sequential_sum = 0.0;
        double seq_start = MPI_Wtime();

        for (long long i = 0; i < N; ++i) {
            double x = static_cast<double>((i % 10000) + 1);
            sequential_sum += calculate_score(x);
        }

        double sequential_time = MPI_Wtime() - seq_start;
        bool correct = abs(global_sum - sequential_sum)
                       <= 1e-8 * max(1.0, abs(sequential_sum));

        cout << fixed << setprecision(6);
        cout << "\n===== ThreatPulse MPI Benchmark =====\n";
        cout << "Workload size       : " << N << '\n';
        cout << "MPI processes       : " << size << '\n';
        cout << "Sequential time     : " << sequential_time << " seconds\n";
        cout << "MPI time            : " << max_elapsed << " seconds\n";
        cout << "Speedup             : "
             << sequential_time / max_elapsed << "x\n";
        cout << "Parallel efficiency : "
             << (sequential_time / max_elapsed) / size * 100.0 << "%\n";
        cout << "Results match       : " << (correct ? "YES" : "NO") << '\n';
    }

    MPI_Finalize();
    return 0;
}
