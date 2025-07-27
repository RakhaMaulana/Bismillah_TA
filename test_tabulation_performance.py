#!/usr/bin/env python3
"""
QUICK TABULATION PERFORMANCE TEST
Simple test untuk memverifikasi optimasi tabulation performance
"""

import time
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_ultra_fast_tabulation():
    """Test ultra-fast tabulation implementation"""
    print("⚡ TESTING ULTRA-FAST TABULATION")
    print("=" * 40)

    try:
        from ultra_fast_recap import UltraOptimizedTabulator

        # Initialize tabulator
        tabulator = UltraOptimizedTabulator(use_parallel=True)

        # Run single test
        print("Running single tabulation test...")
        start_time = time.perf_counter()
        verified_ballots, vote_counts, candidates = tabulator.ultra_fast_tabulation()
        elapsed_time = (time.perf_counter() - start_time) * 1000

        ballot_count = len(verified_ballots)
        per_ballot_time = elapsed_time / ballot_count if ballot_count > 0 else 0

        print(f"\n📊 RESULTS:")
        print(f"Total ballots: {ballot_count}")
        print(f"Total time: {elapsed_time:.2f}ms")
        print(f"Per ballot: {per_ballot_time:.2f}ms")
        print(f"Target: <3.9ms per ballot")
        print(f"Current baseline: 23.3ms per ballot")

        # Performance analysis
        target_achieved = per_ballot_time < 3.9
        improvement_factor = 23.3 / per_ballot_time if per_ballot_time > 0 else 0

        print(f"\n🎯 PERFORMANCE:")
        print(f"Target achieved: {'✅ YES' if target_achieved else '❌ NO'}")
        print(f"Improvement: {improvement_factor:.1f}x faster than baseline")

        if target_achieved:
            print(f"\n🚀 SUCCESS! Ultra-fast tabulation meets zkVoting research target")
            vs_zkvoting = per_ballot_time / 3.9
            print(f"Performance vs zkVoting: {vs_zkvoting:.2f}x")
        else:
            needed_improvement = per_ballot_time / 3.9
            print(f"\n⚠️  Need {needed_improvement:.1f}x more improvement to reach target")

        return {
            'success': True,
            'ballot_count': ballot_count,
            'total_time_ms': elapsed_time,
            'per_ballot_ms': per_ballot_time,
            'target_achieved': target_achieved,
            'improvement_factor': improvement_factor
        }

    except ImportError as e:
        print(f"❌ Error importing ultra-fast tabulation: {e}")
        return {'success': False, 'error': str(e)}
    except Exception as e:
        print(f"❌ Error during tabulation test: {e}")
        return {'success': False, 'error': str(e)}

def compare_implementations():
    """Quick comparison of all implementations"""
    print("\n🔄 COMPARING ALL IMPLEMENTATIONS")
    print("=" * 40)

    implementations = []

    # Test original
    try:
        from Recap import recap_votes
        print("Testing Original implementation...")
        start = time.perf_counter()
        verified_ballots, _, _ = recap_votes()
        elapsed = (time.perf_counter() - start) * 1000
        per_ballot = elapsed / len(verified_ballots) if verified_ballots else 0
        implementations.append(('Original', elapsed, per_ballot, len(verified_ballots)))
        print(f"  Original: {per_ballot:.2f}ms per ballot")
    except Exception as e:
        print(f"  Original failed: {e}")

    # Test ultra-fast sequential
    try:
        from ultra_fast_recap import UltraOptimizedTabulator
        print("Testing Ultra-Fast Sequential implementation...")
        tabulator = UltraOptimizedTabulator(use_parallel=False)
        start = time.perf_counter()
        verified_ballots, _, _ = tabulator.ultra_fast_tabulation()
        elapsed = (time.perf_counter() - start) * 1000
        per_ballot = elapsed / len(verified_ballots) if verified_ballots else 0
        implementations.append(('Ultra-Fast Sequential', elapsed, per_ballot, len(verified_ballots)))
        print(f"  Ultra-Fast Sequential: {per_ballot:.2f}ms per ballot")
    except Exception as e:
        print(f"  Ultra-Fast Sequential failed: {e}")

    # Test ultra-fast
    try:
        from ultra_fast_recap import UltraOptimizedTabulator
        print("Testing Ultra-Fast implementation...")
        tabulator = UltraOptimizedTabulator(use_parallel=True)
        start = time.perf_counter()
        verified_ballots, _, _ = tabulator.ultra_fast_tabulation()
        elapsed = (time.perf_counter() - start) * 1000
        per_ballot = elapsed / len(verified_ballots) if verified_ballots else 0
        implementations.append(('Ultra-Fast', elapsed, per_ballot, len(verified_ballots)))
        print(f"  Ultra-Fast: {per_ballot:.2f}ms per ballot")
    except Exception as e:
        print(f"  Ultra-Fast failed: {e}")

    # Show comparison
    if implementations:
        print(f"\n📈 PERFORMANCE COMPARISON:")
        print(f"{'Implementation':<15} {'Per Ballot (ms)':<15} {'vs Target':<12} {'Status'}")
        print("-" * 60)

        for name, total_ms, per_ballot_ms, ballot_count in implementations:
            vs_target = per_ballot_ms / 3.9
            status = "✅ PASS" if per_ballot_ms < 3.9 else "❌ FAIL"
            print(f"{name:<15} {per_ballot_ms:<15.2f} {vs_target:<12.2f} {status}")

        # Best implementation
        best = min(implementations, key=lambda x: x[2])
        print(f"\n🏆 BEST: {best[0]} at {best[2]:.2f}ms per ballot")

def main():
    """Main test runner"""
    print("🧪 TABULATION PERFORMANCE TEST")
    print("=" * 50)

    # Quick single test
    result = test_ultra_fast_tabulation()

    if result['success']:
        # Compare all implementations
        compare_implementations()

        print(f"\n✅ TEST COMPLETED")
        print(f"Ultra-fast tabulation: {result['per_ballot_ms']:.2f}ms per ballot")
        print(f"Target achieved: {'YES' if result['target_achieved'] else 'NO'}")
    else:
        print(f"\n❌ TEST FAILED: {result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    main()
