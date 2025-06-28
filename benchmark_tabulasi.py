import time
import statistics
from createdb import get_db_connection
from Recap import recap_votes

def measure_recap_performance(iterations=5):
    """Measure the performance of vote tabulation/recap"""
    print(f"📊 Running tabulation benchmark with {iterations} iterations...")

    # Check if we have ballots to tabulate
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM ballots")
    total_ballots = c.fetchone()[0]
    conn.close()

    if total_ballots == 0:
        raise Exception("No ballots found in database. Generate some votes first.")

    print(f"   Found {total_ballots} ballots to tabulate")

    # Perform multiple tabulation runs
    execution_times = []

    for i in range(iterations):
        print(f"   Running iteration {i+1}/{iterations}...")

        start_time = time.time()

        try:
            # Run the actual recap/tabulation function
            verified_ballots, vote_counts, candidates = recap_votes()

            end_time = time.time()
            iteration_time = end_time - start_time
            execution_times.append(iteration_time)

            print(f"     ✅ Iteration {i+1} completed in {iteration_time:.4f}s")

        except Exception as e:
            print(f"     ❌ Iteration {i+1} failed: {str(e)}")
            continue

    if not execution_times:
        raise Exception("All tabulation iterations failed")

    # Calculate statistics
    avg_time = statistics.mean(execution_times)
    median_time = statistics.median(execution_times)
    min_time = min(execution_times)
    max_time = max(execution_times)
    std_dev = statistics.stdev(execution_times) if len(execution_times) > 1 else 0

    # Calculate per-ballot metrics
    avg_time_per_ballot = avg_time / total_ballots if total_ballots > 0 else 0

    # Calculate throughput
    ballots_per_second = total_ballots / avg_time if avg_time > 0 else 0

    results = {
        'total_ballots': total_ballots,
        'iterations': len(execution_times),
        'execution_times': execution_times,
        'avg_time': avg_time,
        'median_time': median_time,
        'min_time': min_time,
        'max_time': max_time,
        'std_dev': std_dev,
        'avg_time_per_ballot': avg_time_per_ballot,
        'ballots_per_second': ballots_per_second
    }

    print(f"✅ Tabulation benchmark completed:")
    print(f"   - Total ballots: {total_ballots}")
    print(f"   - Successful iterations: {len(execution_times)}")
    print(f"   - Average time: {avg_time:.4f}s")
    print(f"   - Median time: {median_time:.4f}s")
    print(f"   - Time per ballot: {avg_time_per_ballot:.8f}s")
    print(f"   - Ballots per second: {ballots_per_second:.2f}")

    return results

def benchmark_comparison():
    """Compare performance with zkVoting system"""
    print("🏁 zkVoting Comparison Benchmark")
    print("=" * 40)

    try:
        # Run our benchmark
        our_results = measure_recap_performance(5)

        # zkVoting benchmark data from research paper
        zkvoting_ballot_casting_time = 2.3  # 2.3 seconds per ballot casting
        zkvoting_tally_time_per_ballot = 0.0039  # 3.9 milliseconds per ballot = 0.0039 seconds

        # Calculate speedup for tabulation (tally process)
        our_time_per_ballot = our_results['avg_time_per_ballot']
        tally_speedup = zkvoting_tally_time_per_ballot / our_time_per_ballot if our_time_per_ballot > 0 else 0

        print(f"\n🏆 Comparison Results:")
        print(f"   📊 TABULATION/TALLY PERFORMANCE:")
        print(f"   Our system: {our_time_per_ballot:.8f}s per ballot")
        print(f"   zkVoting: {zkvoting_tally_time_per_ballot:.6f}s per ballot")
        print(f"   Tally speedup: {tally_speedup:.2f}x {'faster' if tally_speedup > 1 else 'slower'} than zkVoting")

        print(f"\n   📝 BALLOT CASTING REFERENCE:")
        print(f"   zkVoting ballot casting: {zkvoting_ballot_casting_time:.1f}s per ballot")
        print(f"   (Note: Our system focuses on tabulation efficiency)")

        # Performance assessment
        if tally_speedup > 2:
            print(f"   🚀 EXCELLENT: Your tabulation is significantly faster than zkVoting!")
        elif tally_speedup > 1:
            print(f"   ✅ VERY GOOD: Your tabulation outperforms zkVoting")
        elif tally_speedup > 0.5:
            print(f"   👍 COMPETITIVE: Performance is comparable to zkVoting")
        elif tally_speedup > 0.1:
            print(f"   ⚠️ FAIR: Consider optimizations to match zkVoting performance")
        else:
            print(f"   ❌ NEEDS IMPROVEMENT: Significant optimization required")

        # Additional context
        print(f"\n   📋 zkVoting Research Context:")
        print(f"   - Paper: 'zkVoting: A coercion-resistant e-voting system'")
        print(f"   - Algorithm complexity: O(n)")
        print(f"   - Features: Coercion-resistant, E2E verifiable, Zero-knowledge proofs")
        print(f"   - Tally throughput: ~{1/zkvoting_tally_time_per_ballot:.0f} ballots/second")

        return {
            'our_results': our_results,
            'zkvoting_casting_time': zkvoting_ballot_casting_time,
            'zkvoting_tally_time': zkvoting_tally_time_per_ballot,
            'tally_speedup': tally_speedup,
            'comparison_type': 'zkVoting Research'
        }

    except Exception as e:
        print(f"❌ Benchmark failed: {str(e)}")
        return None

def benchmark_vote_verification(num_samples=100):
    """Benchmark vote signature verification performance"""
    print(f"🔐 Running vote verification benchmark with {num_samples} samples...")

    # Get sample ballots
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT candidate_id, signature, type FROM ballots LIMIT ?", (num_samples,))
    ballots = c.fetchall()

    # Get cryptographic keys
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()
    conn.close()

    if not ballots:
        raise Exception("No ballots found for verification benchmark")

    if not key:
        raise Exception("No cryptographic keys found")

    n, e, d = int(key[0]), int(key[1]), int(key[2])

    # Import BlindSig for verification
    import BlindSig as bs

    verification_times = []
    successful_verifications = 0

    print(f"   Verifying {len(ballots)} ballot signatures...")

    for i, ballot in enumerate(ballots):
        candidate_id, signature, ballot_type = ballot

        start_time = time.time()

        try:
            # Verify signature
            is_valid = bs.verify_signature(str(candidate_id), int(signature), e, n)

            end_time = time.time()
            verification_time = end_time - start_time
            verification_times.append(verification_time)

            if is_valid:
                successful_verifications += 1

        except Exception as e:
            end_time = time.time()
            verification_times.append(end_time - start_time)
            continue

        # Progress update
        if (i + 1) % max(1, len(ballots) // 5) == 0:
            progress = ((i + 1) / len(ballots)) * 100
            print(f"     Progress: {progress:.0f}% ({i+1}/{len(ballots)})")

    # Calculate statistics
    avg_verification_time = statistics.mean(verification_times) if verification_times else 0
    min_verification_time = min(verification_times) if verification_times else 0
    max_verification_time = max(verification_times) if verification_times else 0
    total_verification_time = sum(verification_times)

    verification_rate = (successful_verifications / len(ballots)) * 100 if ballots else 0
    verifications_per_second = len(ballots) / total_verification_time if total_verification_time > 0 else 0

    results = {
        'total_ballots_tested': len(ballots),
        'successful_verifications': successful_verifications,
        'verification_success_rate': verification_rate,
        'total_time': total_verification_time,
        'avg_time_per_verification': avg_verification_time,
        'min_time': min_verification_time,
        'max_time': max_verification_time,
        'verifications_per_second': verifications_per_second,
        'verification_times': verification_times
    }

    print(f"✅ Verification benchmark completed:")
    print(f"   - Ballots tested: {len(ballots)}")
    print(f"   - Successful verifications: {successful_verifications}")
    print(f"   - Success rate: {verification_rate:.1f}%")
    print(f"   - Avg time per verification: {avg_verification_time:.8f}s")
    print(f"   - Verifications per second: {verifications_per_second:.2f}")

    return results

def full_system_benchmark(iterations=3):
    """Run a comprehensive benchmark of the entire system vs zkVoting"""
    print("🚀 Running Full System Benchmark vs zkVoting")
    print("=" * 55)

    results = {}

    try:
        # 1. Tabulation benchmark
        print("\n1️⃣ TABULATION BENCHMARK")
        results['tabulation'] = measure_recap_performance(iterations)

        # 2. Verification benchmark
        print("\n2️⃣ VERIFICATION BENCHMARK")
        results['verification'] = benchmark_vote_verification(min(100, results['tabulation']['total_ballots']))

        # 3. Overall system performance vs zkVoting
        print("\n3️⃣ OVERALL SYSTEM ANALYSIS vs zkVoting")

        total_ballots = results['tabulation']['total_ballots']
        tabulation_time = results['tabulation']['avg_time']
        verification_time = results['verification']['total_time']

        # Calculate end-to-end metrics
        end_to_end_time = tabulation_time + verification_time
        end_to_end_per_ballot = end_to_end_time / total_ballots if total_ballots > 0 else 0

        # zkVoting comparison data
        zkvoting_ballot_casting_time = 2.3  # 2.3 seconds per ballot
        zkvoting_tally_time = 0.0039  # 3.9 milliseconds per ballot

        # Calculate speedups vs zkVoting
        tally_speedup = zkvoting_tally_time / (tabulation_time / total_ballots) if tabulation_time > 0 and total_ballots > 0 else 0
        end_to_end_speedup = zkvoting_ballot_casting_time / end_to_end_per_ballot if end_to_end_per_ballot > 0 else 0

        results['overall'] = {
            'total_ballots': total_ballots,
            'end_to_end_time': end_to_end_time,
            'end_to_end_per_ballot': end_to_end_per_ballot,
            'tally_speedup_vs_zkvoting': tally_speedup,
            'end_to_end_speedup_vs_zkvoting': end_to_end_speedup,
            'tabulation_portion': (tabulation_time / end_to_end_time) * 100 if end_to_end_time > 0 else 0,
            'verification_portion': (verification_time / end_to_end_time) * 100 if end_to_end_time > 0 else 0,
            'zkvoting_baseline': {
                'ballot_casting_time': zkvoting_ballot_casting_time,
                'tally_time_per_ballot': zkvoting_tally_time,
                'paper_reference': 'zkVoting: A coercion-resistant e-voting system'
            }
        }

        print(f"   📊 End-to-End Performance:")
        print(f"   - Total time: {end_to_end_time:.4f}s")
        print(f"   - Time per ballot: {end_to_end_per_ballot:.8f}s")
        print(f"   - Tabulation: {results['overall']['tabulation_portion']:.1f}% of total time")
        print(f"   - Verification: {results['overall']['verification_portion']:.1f}% of total time")

        print(f"\n   🏆 zkVoting Comparison:")
        print(f"   - Tally speedup: {tally_speedup:.2f}x {'faster' if tally_speedup > 1 else 'slower'}")
        print(f"   - End-to-end speedup: {end_to_end_speedup:.2f}x {'faster' if end_to_end_speedup > 1 else 'slower'}")
        print(f"   - zkVoting ballot casting: {zkvoting_ballot_casting_time:.1f}s")
        print(f"   - zkVoting tally: {zkvoting_tally_time:.6f}s per ballot")

        # Performance assessment
        if tally_speedup > 2 and end_to_end_speedup > 1:
            performance_rating = "🚀 EXCEPTIONAL"
        elif tally_speedup > 1 and end_to_end_speedup > 0.5:
            performance_rating = "✅ EXCELLENT"
        elif tally_speedup > 0.5:
            performance_rating = "👍 COMPETITIVE"
        else:
            performance_rating = "⚠️ NEEDS IMPROVEMENT"

        print(f"\n   🎯 Performance Rating: {performance_rating}")

        return results

    except Exception as e:
        print(f"❌ Full system benchmark failed: {str(e)}")
        return None

def benchmark_vote_decryption(iterations=5):
    """Benchmark vote decryption/verification for integration with app.py"""
    print(f"🔓 Running vote decryption benchmark with {iterations} iterations...")

    # Get ballots for verification
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT candidate_id, signature, type FROM ballots LIMIT 100")
    ballots = c.fetchall()

    # Get keys
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()
    conn.close()

    if not ballots:
        return {
            'total_votes_verified': 0,
            'avg_time_per_vote': 0,
            'verification_success_rate': 0
        }

    if not key:
        return {
            'total_votes_verified': 0,
            'avg_time_per_vote': 0,
            'verification_success_rate': 0
        }

    n, e, d = int(key[0]), int(key[1]), int(key[2])
    import BlindSig as bs

    total_verification_times = []
    successful_verifications = 0

    for iteration in range(iterations):
        iteration_times = []
        iteration_successes = 0

        for candidate_id, signature, ballot_type in ballots:
            start_time = time.time()

            try:
                is_valid = bs.verify_signature(str(candidate_id), int(signature), e, n)
                if is_valid:
                    iteration_successes += 1
            except:
                pass

            end_time = time.time()
            iteration_times.append(end_time - start_time)

        total_verification_times.extend(iteration_times)
        successful_verifications = max(successful_verifications, iteration_successes)

    avg_time_per_vote = statistics.mean(total_verification_times) if total_verification_times else 0
    verification_success_rate = (successful_verifications / len(ballots)) * 100 if ballots else 0

    results = {
        'total_votes_verified': len(ballots),
        'avg_time_per_vote': avg_time_per_vote,
        'verification_success_rate': verification_success_rate
    }

    print(f"✅ Decryption benchmark completed:")
    print(f"   - Votes verified: {len(ballots)}")
    print(f"   - Avg time per vote: {avg_time_per_vote:.8f}s")
    print(f"   - Success rate: {verification_success_rate:.1f}%")

    return results

def main():
    """Interactive main function"""
    print("📊 Tabulation Benchmark Tool")
    print("🔬 Now with zkVoting Research Comparison!")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("1. Run tabulation benchmark")
        print("2. Compare with zkVoting Research")
        print("3. Run verification benchmark")
        print("4. Full system benchmark vs zkVoting")
        print("5. Check ballot count")
        print("6. zkVoting baseline info")
        print("7. Exit")

        choice = input("\nSelect option (1-7): ").strip()

        if choice == '1':
            try:
                iterations = int(input("Number of iterations (default 5): ") or "5")
                results = measure_recap_performance(iterations)

                print(f"\n📈 Detailed Results:")
                print(f"Min time: {results['min_time']:.4f}s")
                print(f"Max time: {results['max_time']:.4f}s")
                print(f"Std deviation: {results['std_dev']:.4f}s")

            except ValueError:
                print("❌ Invalid number")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '2':
            benchmark_comparison()

        elif choice == '3':
            try:
                num_samples = int(input("Number of ballots to verify (default 100): ") or "100")
                results = benchmark_vote_verification(num_samples)

                print(f"\n📈 Verification Details:")
                print(f"Min time: {results['min_time']:.8f}s")
                print(f"Max time: {results['max_time']:.8f}s")

            except ValueError:
                print("❌ Invalid number")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '4':
            try:
                iterations = int(input("Number of iterations (default 3): ") or "3")
                results = full_system_benchmark(iterations)

                if results:
                    print(f"\n🎯 System Performance Summary:")
                    print(f"Tabulation efficiency: {results['tabulation']['ballots_per_second']:.2f} ballots/sec")
                    print(f"Verification efficiency: {results['verification']['verifications_per_second']:.2f} verifications/sec")
                    print(f"Tally speedup vs zkVoting: {results['overall']['tally_speedup_vs_zkvoting']:.2f}x")
                    print(f"End-to-end speedup vs zkVoting: {results['overall']['end_to_end_speedup_vs_zkvoting']:.2f}x")

            except ValueError:
                print("❌ Invalid number")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '5':
            try:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM ballots")
                ballot_count = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM ballots WHERE type = 'senat'")
                senat_count = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM ballots WHERE type = 'demus'")
                demus_count = c.fetchone()[0]
                conn.close()

                print(f"📊 Ballot Status:")
                print(f"   - Total ballots: {ballot_count}")
                print(f"   - Senat votes: {senat_count}")
                print(f"   - Demus votes: {demus_count}")

            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '6':
            print("🔬 zkVoting Research Baseline Information")
            print("=" * 45)
            print("📋 Paper: 'zkVoting: A coercion-resistant e-voting system'")
            print("🏆 Performance Metrics:")
            print("   - Ballot casting time: 2.3 seconds per ballot")
            print("   - Tally time: 3.9 milliseconds per ballot")
            print("   - Algorithm complexity: O(n)")
            print("   - Throughput: ~256 ballots/second (tally)")
            print("\n✨ Key Features:")
            print("   - Coercion-resistant using fake keys approach")
            print("   - End-to-end verifiability")
            print("   - Voter anonymity preservation")
            print("   - Zero-knowledge proofs integration")
            print("   - Nullifiable commitment scheme")
            print("\n📊 Use Case:")
            print("   - Real-world e-voting applications")
            print("   - Large-scale elections")
            print("   - Research-grade security")

        elif choice == '7':
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()