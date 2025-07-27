#!/usr/bin/env python3
"""
ULTRA-FAST TABULATION PERFORMANCE TESTING SCRIPT
Comprehensive benchmark untuk ultra-fast tabulation implementation
Target: <3.9ms per ballot (dibandingkan dengan zkVoting research)
"""

import time
import sys
import os
import statistics
from typing import Dict, List
import json

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ultra_fast_recap import UltraOptimizedTabulator

def run_ultra_fast_benchmark(iterations: int = 5) -> Dict:
    """Benchmark ultra-fast implementation"""
    print("⚡ Testing Ultra-Fast Tabulation Implementation...")

    tabulator = UltraOptimizedTabulator(use_parallel=True)
    times = []
    ballots_count = 0

    for i in range(iterations):
        start = time.perf_counter()
        verified_ballots, vote_counts, candidates = tabulator.ultra_fast_tabulation()
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
        ballots_count = len(verified_ballots)
        print(f"  Iteration {i+1}: {elapsed:.2f}ms")

    avg_time = statistics.mean(times)
    per_ballot = avg_time / ballots_count if ballots_count > 0 else 0

    return {
        'name': 'Ultra-Fast Tabulation',
        'average_total_ms': avg_time,
        'std_deviation_ms': statistics.stdev(times) if len(times) > 1 else 0,
        'min_time_ms': min(times),
        'max_time_ms': max(times),
        'per_ballot_ms': per_ballot,
        'total_ballots': ballots_count,
        'all_times': times
    }

def run_ultra_fast_sequential_benchmark(iterations: int = 5) -> Dict:
    """Benchmark ultra-fast implementation without parallel processing"""
    print("⚡ Testing Ultra-Fast Tabulation (Sequential)...")

    tabulator = UltraOptimizedTabulator(use_parallel=False)
    times = []
    ballots_count = 0

    for i in range(iterations):
        start = time.perf_counter()
        verified_ballots, vote_counts, candidates = tabulator.ultra_fast_tabulation()
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
        ballots_count = len(verified_ballots)
        print(f"  Iteration {i+1}: {elapsed:.2f}ms")

    avg_time = statistics.mean(times)
    per_ballot = avg_time / ballots_count if ballots_count > 0 else 0

    return {
        'name': 'Ultra-Fast Sequential',
        'average_total_ms': avg_time,
        'std_deviation_ms': statistics.stdev(times) if len(times) > 1 else 0,
        'min_time_ms': min(times),
        'max_time_ms': max(times),
        'per_ballot_ms': per_ballot,
        'total_ballots': ballots_count,
        'all_times': times
    }

def print_comparison_table(results: List[Dict]):
    """Print formatted comparison table"""
    print("\n" + "=" * 100)
    print(f"{'Implementation':<25} {'Avg Total (ms)':<15} {'Per Ballot (ms)':<15} {'vs zkVoting':<12} {'Target':<10}")
    print("=" * 100)

    zkvoting_per_ballot = 3.9  # zkVoting research target performance

    for result in results:
        improvement = zkvoting_per_ballot / result['per_ballot_ms']
        target_status = "✅ PASS" if result['per_ballot_ms'] < zkvoting_per_ballot else "❌ FAIL"

        print(f"{result['name']:<25} {result['average_total_ms']:<15.2f} {result['per_ballot_ms']:<15.2f} {improvement:<12.1f}x {target_status:<10}")

    print("=" * 100)

def generate_performance_report(results: List[Dict]) -> str:
    """Generate detailed performance report"""
    report = []
    report.append("ULTRA-FAST TABULATION PERFORMANCE ANALYSIS REPORT")
    report.append("=" * 60)
    report.append("")

    zkvoting_target = 3.9  # zkVoting research target
    report.append(f"zkVoting Research Target: {zkvoting_target}ms per ballot")
    report.append("")

    for result in results:
        improvement = zkvoting_target / result['per_ballot_ms']
        target_achieved = result['per_ballot_ms'] < zkvoting_target

        report.append(f"Implementation: {result['name']}")
        report.append(f"  Average Total Time: {result['average_total_ms']:.2f}ms ± {result['std_deviation_ms']:.2f}ms")
        report.append(f"  Per Ballot Time: {result['per_ballot_ms']:.2f}ms")
        report.append(f"  Total Ballots: {result['total_ballots']}")
        report.append(f"  vs zkVoting: {improvement:.1f}x faster")
        report.append(f"  Target Achieved: {'✅ YES' if target_achieved else '❌ NO'}")
        report.append(f"  Time Range: {result['min_time_ms']:.2f}ms - {result['max_time_ms']:.2f}ms")
        report.append("")

    # Best performance
    best_result = min(results, key=lambda x: x['per_ballot_ms'])
    report.append(f"🏆 BEST PERFORMANCE: {best_result['name']}")
    report.append(f"   {best_result['per_ballot_ms']:.2f}ms per ballot")
    report.append(f"   {zkvoting_target / best_result['per_ballot_ms']:.1f}x faster than zkVoting target")

    return "\n".join(report)

def main():
    """Main benchmark runner untuk ultra-fast tabulation"""
    print("⚡ ULTRA-FAST TABULATION PERFORMANCE BENCHMARK")
    print("=" * 60)
    print("Target: Beat zkVoting research performance of 3.9ms per ballot")
    print()

    iterations = 5

    try:
        # Run ultra-fast benchmarks
        results = []

        # Ultra-fast parallel implementation
        ultra_fast_result = run_ultra_fast_benchmark(iterations)
        results.append(ultra_fast_result)

        # Ultra-fast sequential implementation
        ultra_fast_seq_result = run_ultra_fast_sequential_benchmark(iterations)
        results.append(ultra_fast_seq_result)

        # Print comparison
        print_comparison_table(results)

        # Generate detailed report
        report = generate_performance_report(results)
        print("\n" + report)

        # Save results to file
        with open('ultra_fast_tabulation_benchmark.json', 'w') as f:
            json.dump(results, f, indent=2)

        with open('ultra_fast_tabulation_report.txt', 'w') as f:
            f.write(report)

        print(f"\n📄 Results saved to:")
        print(f"  - ultra_fast_tabulation_benchmark.json")
        print(f"  - ultra_fast_tabulation_report.txt")

        # Check if target achieved
        best_per_ballot = min(result['per_ballot_ms'] for result in results)
        if best_per_ballot < 3.9:
            improvement = 3.9 / best_per_ballot
            print(f"\n🎯 TARGET ACHIEVED! Best performance: {best_per_ballot:.3f}ms per ballot")
            print(f"🚀 {improvement:.1f}x FASTER than zkVoting research target!")
        else:
            print(f"\n⚠️  Target missed. Best performance: {best_per_ballot:.2f}ms per ballot (target: 3.9ms)")

    except Exception as e:
        print(f"❌ Error during benchmark: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
