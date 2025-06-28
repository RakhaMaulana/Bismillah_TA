import time
import random
import hashlib
import statistics
from createdb import get_db_connection, save_ballot, save_candidate
import BlindSig as bs

def get_or_create_keys():
    """Get existing keys or create new ones"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()

    if key:
        n, e, d = int(key[0]), int(key[1]), int(key[2])
        conn.close()
        return n, e, d
    else:
        # Create new keys
        signer = bs.Signer()
        public_key = signer.get_public_key()
        n = public_key['n']
        e = public_key['e']
        d = signer.private_key['d']

        c.execute("INSERT INTO keys (n, e, d, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                  (str(n), str(e), str(d)))
        conn.commit()
        conn.close()
        return n, e, d

def create_dummy_candidates():
    """Create dummy candidates if none exist"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM candidates")
    count = c.fetchone()[0]

    if count == 0:
        # Create dummy candidates
        dummy_candidates = [
            ("Alice Johnson", "uploads/dummy1.jpg", "4A", "senat"),
            ("Bob Smith", "uploads/dummy2.jpg", "4B", "senat"),
            ("Charlie Brown", "uploads/dummy3.jpg", "4C", "demus"),
            ("Diana Wilson", "uploads/dummy4.jpg", "4D", "demus"),
        ]

        for name, photo, class_name, candidate_type in dummy_candidates:
            save_candidate(name, photo, class_name, candidate_type)

        print(f"✅ Created {len(dummy_candidates)} dummy candidates")

    conn.close()

def generate_dummy_votes_with_timing(num_votes, measure_individual=False):
    """Generate dummy votes with performance measurement"""
    print(f"🚀 Starting generation of {num_votes} dummy votes...")

    # Ensure we have candidates
    create_dummy_candidates()

    # Get available candidates
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, type FROM candidates")
    candidates = c.fetchall()
    conn.close()

    if not candidates:
        raise Exception("No candidates found")

    # Get or create cryptographic keys
    n, e, d = get_or_create_keys()

    # Setup signer
    signer = bs.Signer()
    signer.public_key = {'n': n, 'e': e}
    signer.private_key = {'d': d}

    # Performance tracking
    start_time = time.time()
    individual_times = [] if measure_individual else None
    successful_votes = 0
    failed_votes = 0

    for i in range(num_votes):
        vote_start = time.time() if measure_individual else None

        try:
            # Select random candidate
            candidate = random.choice(candidates)
            candidate_id = candidate['id']
            candidate_type = candidate['type']

            # Generate vote with blind signature
            message = str(candidate_id)
            message_hash = hashlib.sha256(message.encode()).hexdigest()
            message_hash_int = int(message_hash, 16)

            # Create voter and blind message
            voter_obj = bs.Voter(n, "y")
            blind_message = voter_obj.blind_message(message_hash_int, n, e)

            # Sign blinded message
            signed_blind_message = signer.sign_message(blind_message, voter_obj.get_eligibility())

            # Unwrap signature
            signature = voter_obj.unwrap_signature(signed_blind_message, n)

            # Verify signature
            is_valid = bs.verify_signature(message, signature, e, n)

            if is_valid:
                # Save to database
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("INSERT INTO ballots (candidate_id, signature, type) VALUES (?, ?, ?)",
                         (candidate_id, str(signature), candidate_type))
                conn.commit()
                conn.close()
                successful_votes += 1
            else:
                failed_votes += 1

        except Exception as e:
            failed_votes += 1
            print(f"   ❌ Vote {i+1} failed: {str(e)}")

        if measure_individual and vote_start:
            vote_end = time.time()
            individual_times.append(vote_end - vote_start)

        # Progress indicator
        if (i + 1) % max(1, num_votes // 10) == 0:
            progress = ((i + 1) / num_votes) * 100
            print(f"   📊 Progress: {progress:.0f}% ({i+1}/{num_votes})")

    end_time = time.time()
    total_time = end_time - start_time

    # Calculate statistics
    avg_time_per_vote = total_time / num_votes if num_votes > 0 else 0
    votes_per_second = successful_votes / total_time if total_time > 0 else 0
    success_rate = (successful_votes / num_votes) * 100 if num_votes > 0 else 0

    # Individual statistics
    individual_stats = {}
    if individual_times:
        individual_stats = {
            'min': min(individual_times),
            'max': max(individual_times),
            'median': statistics.median(individual_times),
            'std_dev': statistics.stdev(individual_times) if len(individual_times) > 1 else 0
        }

    results = {
        'successful_votes': successful_votes,
        'failed_votes': failed_votes,
        'total_time': total_time,
        'avg_time_per_vote': avg_time_per_vote,
        'votes_per_second': votes_per_second,
        'success_rate': success_rate,
        'individual_times': individual_times,
        'individual_stats': individual_stats
    }

    print(f"✅ Vote generation completed:")
    print(f"   - Successful: {successful_votes}")
    print(f"   - Failed: {failed_votes}")
    print(f"   - Total time: {total_time:.4f}s")
    print(f"   - Avg time per vote: {avg_time_per_vote:.6f}s")
    print(f"   - Votes per second: {votes_per_second:.2f}")
    print(f"   - Success rate: {success_rate:.1f}%")

    return results

def main():
    """Interactive main function for testing"""
    print("🗳️ Dummy Vote Generator")
    print("=" * 40)

    while True:
        print("\nOptions:")
        print("1. Generate votes with timing")
        print("2. Create dummy candidates")
        print("3. Check current vote count")
        print("4. Exit")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == '1':
            try:
                num_votes = int(input("Number of votes to generate: "))
                measure_individual = input("Measure individual vote times? (y/n): ").lower().startswith('y')

                results = generate_dummy_votes_with_timing(num_votes, measure_individual)

                print(f"\n📊 Results Summary:")
                print(f"Success Rate: {results['success_rate']:.1f}%")
                print(f"Average Time: {results['avg_time_per_vote']:.6f}s per vote")
                print(f"Throughput: {results['votes_per_second']:.2f} votes/sec")

                if results['individual_stats']:
                    stats = results['individual_stats']
                    print(f"Min Time: {stats['min']:.6f}s")
                    print(f"Max Time: {stats['max']:.6f}s")
                    print(f"Median Time: {stats['median']:.6f}s")

            except ValueError:
                print("❌ Invalid number")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '2':
            try:
                create_dummy_candidates()
                print("✅ Dummy candidates created/verified")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '3':
            try:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM ballots")
                ballot_count = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM candidates")
                candidate_count = c.fetchone()[0]
                conn.close()

                print(f"📊 Current Status:")
                print(f"   - Ballots: {ballot_count}")
                print(f"   - Candidates: {candidate_count}")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '4':
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()