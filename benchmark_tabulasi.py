import time
import statistics
from createdb import get_db_connection
from Recap import recap_votes

def measure_recap_performance(iterations=5):
    """Measure the performance of vote tabulation/recap"""

    # Check if we have ballots to tabulate
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM ballots")
    total_ballots = c.fetchone()[0]
    conn.close()

    if total_ballots == 0:
        raise Exception("No ballots found in database. Generate some votes first.")


    # Perform multiple tabulation runs
    execution_times = []

    for i in range(iterations):
        start_time = time.time()
        try:
            verified_ballots, vote_counts, candidates = recap_votes()
            end_time = time.time()
            iteration_time = end_time - start_time
            execution_times.append(iteration_time)
        except Exception as e:
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


    return results

def benchmark_comparison():
    """Compare performance with zkVoting system"""

    try:
        # Run our benchmark
        our_results = measure_recap_performance(5)

        # zkVoting benchmark data from research paper
        zkvoting_ballot_casting_time = 2.3  # 2.3 seconds per ballot casting
        zkvoting_tally_time_per_ballot = 0.0039  # 3.9 milliseconds per ballot = 0.0039 seconds

        # Calculate speedup for tabulation (tally process)
        our_time_per_ballot = our_results['avg_time_per_ballot']
        tally_speedup = zkvoting_tally_time_per_ballot / our_time_per_ballot if our_time_per_ballot > 0 else 0


        return {
            'our_results': our_results,
            'zkvoting_casting_time': zkvoting_ballot_casting_time,
            'zkvoting_tally_time': zkvoting_tally_time_per_ballot,
            'tally_speedup': tally_speedup,
            'comparison_type': 'zkVoting Research'
        }

    except Exception as e:
        return None

def benchmark_vote_verification(num_samples=100):
    """Benchmark vote signature verification performance"""

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


    for i, ballot in enumerate(ballots):
        candidate_id, signature, ballot_type = ballot
        start_time = time.time()
        try:
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


    return results

def full_system_benchmark(iterations=3):
    """Run a comprehensive benchmark of the entire system vs zkVoting"""

    results = {}

    try:
        # 1. Tabulation benchmark
        results['tabulation'] = measure_recap_performance(iterations)
        results['verification'] = benchmark_vote_verification(min(100, results['tabulation']['total_ballots']))
        total_ballots = results['tabulation']['total_ballots']
        tabulation_time = results['tabulation']['avg_time']
        verification_time = results['verification']['total_time']
        end_to_end_time = tabulation_time + verification_time
        end_to_end_per_ballot = end_to_end_time / total_ballots if total_ballots > 0 else 0
        zkvoting_ballot_casting_time = 2.3
        zkvoting_tally_time = 0.0039
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
        return results

    except Exception as e:
        return None

def benchmark_vote_decryption(iterations=5):
    """Benchmark vote decryption/verification for integration with app.py"""

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


    return results

def main():
    """Interactive main function"""

    while True:
        break

if __name__ == "__main__":
    main()