import time
import random
import hashlib
import statistics
import threading
from createdb import get_db_connection, save_ballot, save_candidate
import BlindSig as bs
from key_manager import get_global_signer, get_global_keys

def get_or_create_keys():
    """Get global keys yang konsisten di seluruh sistem"""
    # PERBAIKAN: Gunakan global key manager untuk konsistensi
    keys = get_global_keys()
    print(f"DEBUG: Using global keys: n={keys['n']}, e={keys['e']}")
    return keys

def create_dummy_candidates():
    """Create 16 dummy candidates (8 senat + 8 demus) if none exist"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM candidates")
    count = c.fetchone()[0]

    if count == 0:
        # Create 16 dummy candidates - 8 for senat, 8 for demus
        dummy_candidates = [
            # SENAT CANDIDATES (8)
            ("Alice Johnson", "uploads/senat_alice.jpg", "4A", "senat"),
            ("Bob Smith", "uploads/senat_bob.jpg", "4B", "senat"),
            ("Charlie Brown", "uploads/senat_charlie.jpg", "4C", "senat"),
            ("Diana Wilson", "uploads/senat_diana.jpg", "4D", "senat"),
            ("Edward Davis", "uploads/senat_edward.jpg", "3A", "senat"),
            ("Fiona Martinez", "uploads/senat_fiona.jpg", "3B", "senat"),
            ("George Thompson", "uploads/senat_george.jpg", "3C", "senat"),
            ("Hannah Garcia", "uploads/senat_hannah.jpg", "3D", "senat"),

            # DEMUS CANDIDATES (8)
            ("Ivan Rodriguez", "uploads/demus_ivan.jpg", "4A", "demus"),
            ("Julia Anderson", "uploads/demus_julia.jpg", "4B", "demus"),
            ("Kevin Lee", "uploads/demus_kevin.jpg", "4C", "demus"),
            ("Laura White", "uploads/demus_laura.jpg", "4D", "demus"),
            ("Michael Taylor", "uploads/demus_michael.jpg", "3A", "demus"),
            ("Nina Patel", "uploads/demus_nina.jpg", "3B", "demus"),
            ("Oscar Chen", "uploads/demus_oscar.jpg", "3C", "demus"),
            ("Paula Jackson", "uploads/demus_paula.jpg", "3D", "demus"),
        ]

        senat_count = 0
        demus_count = 0

        for name, photo, class_name, candidate_type in dummy_candidates:
            save_candidate(name, photo, class_name, candidate_type)
            if candidate_type == "senat":
                senat_count += 1
            else:
                demus_count += 1

        print(f"✅ Created {len(dummy_candidates)} dummy candidates:")
        print(f"   - Senat candidates: {senat_count}")
        print(f"   - Demus candidates: {demus_count}")

        # Display candidate list
        print(f"\n📋 SENAT CANDIDATES:")
        senat_candidates = [c for c in dummy_candidates if c[3] == "senat"]
        for i, (name, _, class_name, _) in enumerate(senat_candidates, 1):
            print(f"   {i}. {name} ({class_name})")

        print(f"\n📋 DEMUS CANDIDATES:")
        demus_candidates = [c for c in dummy_candidates if c[3] == "demus"]
        for i, (name, _, class_name, _) in enumerate(demus_candidates, 1):
            print(f"   {i}. {name} ({class_name})")

    else:
        # Check existing candidate distribution
        c.execute("SELECT type, COUNT(*) FROM candidates GROUP BY type")
        distribution = dict(c.fetchall())
        print(f"📊 Existing candidates:")
        print(f"   - Senat: {distribution.get('senat', 0)}")
        print(f"   - Demus: {distribution.get('demus', 0)}")

    conn.close()

def generate_dummy_votes_with_timing(num_votes, measure_individual=False):
    """Generate dummy votes with performance measurement"""
    print(f"🚀 Starting generation of {num_votes} dummy votes...")

    # Ensure we have candidates
    create_dummy_candidates()

    # Get available candidates with distribution info
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, type FROM candidates")
    candidates = c.fetchall()

    # Get candidate distribution
    c.execute("SELECT type, COUNT(*) FROM candidates GROUP BY type")
    distribution = dict(c.fetchall())
    conn.close()

    if not candidates:
        raise Exception("No candidates found")

    print(f"📊 Available candidates: {len(candidates)} total")
    print(f"   - Senat: {distribution.get('senat', 0)}")
    print(f"   - Demus: {distribution.get('demus', 0)}")

    # ✅ FIX: Get cryptographic keys dan signer yang konsisten
    keys = get_or_create_keys()
    signer = get_global_signer()  # Gunakan global signer yang konsisten

    # Performance tracking
    start_time = time.time()
    individual_times = [] if measure_individual else None
    successful_votes = 0
    failed_votes = 0

    # Vote distribution tracking
    vote_distribution = {'senat': {}, 'demus': {}}
    for candidate in candidates:
        vote_distribution[candidate['type']][candidate['name']] = 0

    # Database lock untuk mencegah race condition
    db_lock = threading.Lock()

    # ✅ PERBAIKAN: Sequential processing dengan database transactions
    for i in range(num_votes):
        vote_start = time.time()

        try:
            # Pilih kandidat secara random
            vote_type = 'senat' if i % 2 == 0 else 'demus'
            available_candidates = [c for c in candidates if c['type'] == vote_type]

            if not available_candidates:
                failed_votes += 1
                print(f"   ❌ No candidates available for {vote_type}")
                continue

            selected_candidate = random.choice(available_candidates)
            candidate_id = selected_candidate['id']
            candidate_name = selected_candidate['name']

            # ✅ CRITICAL: Database transaction dengan lock
            with db_lock:  # Ensure atomic database operations
                conn = get_db_connection()
                try:
                    c = conn.cursor()

                    # BEGIN TRANSACTION
                    conn.execute("BEGIN IMMEDIATE;")

                    # ✅ FIX: No need to check current count - just generate as requested
                    # The constraint is removed from database, so duplicates are now allowed

                    # ✅ FIX: Create blind signature with correct keys and unique entropy
                    message = str(candidate_id)
                    message_hash = hashlib.sha256(message.encode()).hexdigest()
                    message_hash_int = int(message_hash, 16)

                    # Create voter object with unique entropy for each vote
                    unique_entropy = f"{candidate_id}_{vote_type}_{i}_{time.time_ns()}"
                    voter = bs.Voter(keys['n'], "y", unique_entropy)
                    blind_message = voter.blind_message(message_hash_int, keys['n'], keys['e'])
                    signed_blind_message = signer.sign_message(blind_message, voter.get_eligibility())
                    signature = voter.unwrap_signature(signed_blind_message, keys['n'])

                    # PERBAIKAN: Simpan hanya signature tanpa candidate_id (blind signature compliance)
                    c.execute("INSERT INTO ballots (signature, type) VALUES (?, ?)",
                             (str(signature), vote_type))

                    # COMMIT TRANSACTION
                    conn.commit()

                    # Update counters
                    vote_distribution[vote_type][candidate_name] += 1
                    successful_votes += 1

                    vote_end = time.time()
                    vote_time = vote_end - vote_start
                    if measure_individual:
                        individual_times.append(vote_time)

                except Exception as e:
                    conn.rollback()
                    failed_votes += 1
                    print(f"   ❌ Vote {i+1} failed: {str(e)}")

                finally:
                    conn.close()

        except Exception as e:
            failed_votes += 1
            print(f"   ❌ Vote {i+1} generation error: {str(e)}")

        # Progress indicator
        if (i + 1) % max(1, num_votes // 10) == 0:
            progress = ((i + 1) / num_votes) * 100
            print(f"   📊 Progress: {progress:.0f}% ({i+1}/{num_votes})")

    end_time = time.time()
    total_time = end_time - start_time

    # ✅ VERIFICATION: Check actual database counts
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM ballots WHERE type = 'senat'")
    actual_senat = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM ballots WHERE type = 'demus'")
    actual_demus = c.fetchone()[0]
    conn.close()

    print(f"✅ Vote generation completed:")
    print(f"   - Target: {num_votes}")
    print(f"   - Successful: {successful_votes}")
    print(f"   - Failed: {failed_votes}")
    print(f"   - Actual in DB: SENAT={actual_senat}, DEMUS={actual_demus}")

    # ✅ FIX: Handle division by zero
    if successful_votes > 0:
        print(f"   - Total time: {total_time:.4f}s")
        print(f"   - Avg time per vote: {total_time/successful_votes:.6f}s")
        print(f"   - Votes per second: {successful_votes/total_time:.2f}")
        print(f"   - Success rate: {(successful_votes/(successful_votes+failed_votes))*100:.1f}%")
    else:
        print(f"   - Total time: {total_time:.4f}s")
        print(f"   - No successful votes generated")
        print(f"   - Success rate: 0%")

    # Display vote distribution only if we have votes
    if successful_votes > 0:
        print(f"\n📊 Vote Distribution:")
        total_senat_votes = sum(vote_distribution['senat'].values())
        total_demus_votes = sum(vote_distribution['demus'].values())

        print(f"   SENAT ({total_senat_votes} votes):")
        for name, count in vote_distribution['senat'].items():
            if count > 0:
                percentage = (count / total_senat_votes * 100) if total_senat_votes > 0 else 0
                print(f"     • {name}: {count} votes ({percentage:.1f}%)")

        print(f"   DEMUS ({total_demus_votes} votes):")
        for name, count in vote_distribution['demus'].items():
            if count > 0:
                percentage = (count / total_demus_votes * 100) if total_demus_votes > 0 else 0
                print(f"     • {name}: {count} votes ({percentage:.1f}%)")

    # ✅ FIX: Safe calculation to avoid division by zero
    avg_time_per_vote = total_time / successful_votes if successful_votes > 0 else 0
    votes_per_second = successful_votes / total_time if total_time > 0 else 0
    success_rate = (successful_votes / (successful_votes + failed_votes)) * 100 if (successful_votes + failed_votes) > 0 else 0

    results = {
        'successful_votes': successful_votes,
        'failed_votes': failed_votes,
        'total_votes': successful_votes,  # Only count successful votes
        'total_time': total_time,
        'avg_time_per_vote': avg_time_per_vote,
        'votes_per_second': votes_per_second,
        'success_rate': success_rate,
        'vote_distribution': vote_distribution
    }

    if measure_individual and individual_times:
        results['individual_stats'] = {
            'min': min(individual_times),
            'max': max(individual_times),
            'median': statistics.median(individual_times),
            'std_dev': statistics.stdev(individual_times) if len(individual_times) > 1 else 0
        }

    return results

def main():
    """Interactive main function for testing"""
    print("🗳️ Dummy Vote Generator (16 Candidates)")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("1. Generate votes with timing")
        print("2. Create dummy candidates (16 total)")
        print("3. Check current vote count")
        print("4. Show candidate list")
        print("5. Clear all votes")
        print("6. Exit")

        choice = input("\nSelect option (1-6): ").strip()

        if choice == '1':
            try:
                num_votes = int(input("Number of votes to generate: "))
                measure_individual = input("Measure individual vote times? (y/n): ").lower().startswith('y')

                results = generate_dummy_votes_with_timing(num_votes, measure_individual)

                print(f"\n📊 Results Summary:")
                print(f"Success Rate: {results['success_rate']:.1f}%")
                print(f"Average Time: {results['avg_time_per_vote']:.6f}s per vote")
                print(f"Throughput: {results['votes_per_second']:.2f} votes/sec")

                if 'individual_stats' in results and results['individual_stats']:
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
                c.execute("SELECT type, COUNT(*) FROM ballots GROUP BY type")
                ballot_distribution = dict(c.fetchall())
                c.execute("SELECT COUNT(*) FROM candidates")
                candidate_count = c.fetchone()[0]
                conn.close()

                print(f"📊 Current Status:")
                print(f"   - Total Ballots: {ballot_count}")
                print(f"   - Senat Votes: {ballot_distribution.get('senat', 0)}")
                print(f"   - Demus Votes: {ballot_distribution.get('demus', 0)}")
                print(f"   - Total Candidates: {candidate_count}")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '4':
            try:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("SELECT name, class, type FROM candidates ORDER BY type, name")
                candidates = c.fetchall()
                conn.close()

                if candidates:
                    senat_candidates = [c for c in candidates if c[2] == 'senat']
                    demus_candidates = [c for c in candidates if c[2] == 'demus']

                    print(f"\n📋 SENAT CANDIDATES ({len(senat_candidates)}):")
                    for i, (name, class_name, _) in enumerate(senat_candidates, 1):
                        print(f"   {i}. {name} ({class_name})")

                    print(f"\n📋 DEMUS CANDIDATES ({len(demus_candidates)}):")
                    for i, (name, class_name, _) in enumerate(demus_candidates, 1):
                        print(f"   {i}. {name} ({class_name})")
                else:
                    print("❌ No candidates found")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '5':
            try:
                confirm = input("⚠️ Clear all votes? This cannot be undone! (yes/no): ").lower()
                if confirm == 'yes':
                    conn = get_db_connection()
                    c = conn.cursor()
                    c.execute("DELETE FROM ballots")
                    conn.commit()
                    deleted_count = c.rowcount
                    conn.close()
                    print(f"✅ Deleted {deleted_count} votes")
                else:
                    print("❌ Operation cancelled")
            except Exception as e:
                print(f"❌ Error: {str(e)}")

        elif choice == '6':
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()