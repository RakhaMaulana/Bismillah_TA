import BlindSig as bs
import hashlib
import secrets
import cryptomath
import sqlite3
from createdb import save_keys, save_voter, save_ballot

yell = '\u001b[33;1m'
reset = '\u001b[0m'
red = '\u001b[31m'
pink = '\u001b[35;1m'


def get_existing_keys():
    conn = sqlite3.connect('evoting.db')
    c = conn.cursor()
    c.execute("SELECT n, e, d FROM keys ORDER BY timestamp DESC LIMIT 1")
    key = c.fetchone()
    conn.close()
    if key:
        n, e, d = int(key[0]), int(key[1]), int(key[2])
        return n, e, d
    return None


class Poll:
    def __init__(self):
        self.initialize_keys()

    def initialize_keys(self):
        existing_keys = get_existing_keys()
        if existing_keys:
            self.n, self.e, self.d = existing_keys
        else:
            self.signer = bs.Signer()
            self.public_key = self.signer.get_public_key()
            self.n = self.public_key['n']
            self.e = self.public_key['e']
            self.d = self.signer.private_key['d']
            save_keys(self.n, self.e, self.d)  # Save keys to the database

    def poll_response(self, poll_answer, eligible_answer):
        eligible_answer = "y" if eligible_answer == 1 else "n"
        self.print_module_header("MODULE 2", "2. Voter Prepares Ballot for getting signed by Signing Authority:")
        x = self.generate_random_x()
        concat_message, message_hash = self.create_concatenated_message(poll_answer, x)
        voter = bs.Voter(self.n, eligible_answer)
        blind_message = voter.blind_message(message_hash, self.n, self.e)
        self.print_blind_message(blind_message, eligible_answer)
        signed_blind_message = self.signer.sign_message(blind_message, voter.get_eligibility())
        self.process_signed_blind_message(signed_blind_message, concat_message, message_hash, blind_message, voter, x)

    def generate_random_x(self):
        x = secrets.randbelow(self.n - 1) + 1
        print("\u001b[35;1m(a) Generates random x such that 1<=x<=n\u001b[0m", end='\n\n')
        print("\u001b[33;1mx: \u001b[0m", x, end="\n\n")
        return x

    @staticmethod
    def create_concatenated_message(poll_answer, x):
        print("\u001b[35;1m(b) Voter chooses favorite candidate, option, etc. on ballot\u001b[0m", end='\n\n')
        print("\u001b[33;1mpoll_answer: \u001b[0m", poll_answer, end="\n\n")
        concat_message = str(poll_answer) + str(x)
        print("\u001b[35;1m(c) Creates (concatenating) message: poll_answer + x and produces it's hash\u001b[0m", end='\n\n')
        print("\u001b[33;1mConcatenated message: \u001b[0m", concat_message, end="\n\n")
        message_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        message_hash = int(message_hash, 16)
        print("\u001b[33;1mhash(concatenated_message), m= \u001b[0m", message_hash, end="\n\n")
        return concat_message, message_hash

    @staticmethod
    def print_blind_message(blind_message, eligible_answer):
        if eligible_answer == "y":
            print("\u001b[33;1mBlinded message: \u001b[0m" + str(blind_message))
        print()

    def process_signed_blind_message(self, signed_blind_message, concat_message, message_hash, blind_message, voter, x):
        if signed_blind_message is None:
            print("\u001b[31;1mINELIGIBLE VOTER....VOTE NOT AUTHORIZED!\u001b[0m")
        else:
            print("\u001b[33;1mSigned blinded message: \u001b[0m" + str(signed_blind_message))
            print()
            signed_message = voter.unwrap_signature(signed_blind_message, self.n)
            self.print_module_header("MODULE 5", "5. Ballot Received and it's Verification")
            self.verify_and_save_ballot(concat_message, message_hash, blind_message, signed_blind_message, signed_message, x)

    def verify_and_save_ballot(self, concat_message, message_hash, blind_message, signed_blind_message, signed_message, x):
        print("\u001b[35;1mA voter's vote in the ballot shall consist of the following: \u001b[0m", end='\n\n')
        print("\u001b[33;1m(a) His vote concatened with a number x: \u001b[0m", concat_message)
        print()
        print("\u001b[33;1m(b) The hash of his concatenated vote signed by authority which is basically the hashed message encrypted with signing authority's private key (m^d) mod n : \u001b[0m", signed_message)
        print()
        verification_status, decoded_message = bs.verify_signature(concat_message[0], x, signed_message, self.e, self.n)
        print("\u001b[33;1mVerification status: \u001b[0m" + str(verification_status), end="\n\n")
        if verification_status:
            print("\u001b[35;1mSince the verification is true, Hence the vote is the first digit of the concatenated message: \u001b[0m", decoded_message, end='\n\n\n\n')
        save_ballot(x, concat_message, message_hash, blind_message, signed_blind_message, signed_message)

    @staticmethod
    def print_module_header(module_name, description):
        print('\n\n')
        for _ in range(100):
            print("-", end="")
        print()
        for _ in range(50):
            print(" ", end="")
        print(f"\u001b[31m{module_name}\u001b[37m")
        for _ in range(100):
            print("-", end="")
        print('\n\n')
        print(f"\u001b[32;1m{description}\u001b[0m", end='\n\n')


class PollMachine:

    def __init__(self):
        self.p = Poll()
        self.run_poll()

    def run_poll(self):
        while True:
            poll_ = self.get_poll_choice()
            self.authenticate_voter(poll_)
            if not self.ask_to_vote_again():
                break

    @staticmethod
    def get_poll_choice():
        print("\u001b[32;1mEnter your choice\u001b[0m")
        print()
        print("(1) Apple     (2) Ball      (3) Rat      (4) Avengers    (5) Elephant")
        poll_ = int(input())
        print()
        while poll_ < 1 or poll_ > 5:
            print("\u001b[31;1mInput", poll_, "is not a valid option. Please enter a valid option:\u001b[0m")
            poll_ = int(input())
            print()
        return poll_

    def authenticate_voter(self, poll_):
        self.print_module_header("Digital Signature Authentication")
        _, _, n, _, public_key, private_key = self.generate_keys()
        id_number, s = self.create_digital_signature(n, private_key)
        save_voter(id_number, s, "placeholder_photo_filename")
        self.verify_digital_signature(id_number, s, public_key, n)
        self.p.poll_response(poll_, 1)

    def generate_keys(self):
        print("\u001b[35;1m(a)Choose two large prime numbers p and q \u001b[0m", end="\n\n")
        p = cryptomath.find_prime()
        print("\u001b[33;1m p: \u001b[0m", p, end="\n\n")
        q = cryptomath.find_prime()
        print("\u001b[33;1m q: \u001b[0m", q, end="\n\n")
        print("\u001b[35;1m(b)Calculate n=p*q \u001b[0m", end="\n\n")
        n = p * q
        print("\u001b[33;1m n: \u001b[0m", n)
        print('\n')
        print("\u001b[35;1m(c)Calculate the totient of n \u001b[0m", end="\n\n")
        phi = (p - 1) * (q - 1)
        print("\u001b[33;1m ϕ(n): \u001b[0m", phi, end="\n\n")
        print("\u001b[35;1m(d) Picks public_key such that gcd(ϕ(n),public_key)=1 & 1<public_key<ϕ(n):\u001b[0m", end='\n\n')
        public_key = self.pick_public_key(phi)
        print("\u001b[33;1me: \u001b[0m", public_key, end='\n\n')
        print("\u001b[35;1m(e) Computes private_key, where private_key is the inverse of public_key modulo ϕ(n)\u001b[0m", end='\n\n')
        private_key = cryptomath.find_mod_inverse(public_key, phi)
        print("\u001b[33;1md: \u001b[0m", private_key, end='\n\n')
        return p, q, n, phi, public_key, private_key

    @staticmethod
    def pick_public_key(phi):
        found_encryption_key = False
        while not found_encryption_key:
            public_key = secrets.randbelow(phi - 1) + 1
            if cryptomath.gcd(public_key, phi) == 1:
                found_encryption_key = True
        return public_key

    @staticmethod
    def create_digital_signature(n, private_key):
        print("\u001b[32;1mEnter id Number: \u001b[0m", end="\n\n")
        id_number = int(input())
        concat_message = str(id_number)
        print("\n\n")
        print("\u001b[35;1m(f) Hash the message (here, message= idNumber) \u001b[0m", end="\n\n")
        id_number_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        id_number_hash = int(id_number_hash, 16)
        print("\u001b[33;1mHash(idNumber): \u001b[0m", id_number_hash, end="\n\n")
        print("\u001b[35;1m(g) Voter creates Digital Signature using s=(message_hash)^(private key)mod n \u001b[0m", end="\n\n")
        s = pow(id_number_hash, private_key, n)  # ERR2
        print("\u001b[33;1mDigital Signature, s: \u001b[0m", s, end="\n\n")
        return id_number, s

    @staticmethod
    def verify_digital_signature(id_number, s, public_key, n):
        print("\u001b[35;1m(h) Digital Signature, s, and original message, idNumber (without hash) are made available to the Verifier \u001b[0m", end="\n\n")
        print("\u001b[35;1m(i) The Verifier calculates and compares the values of the \u001b[0m", '\n\n', "    1. Decrypted message and", '\n\n', "    2. Hash(idNumber)", '\n\n', "\u001b[35;1mIf these 2 values are same then its authenticated using Digital Signature \u001b[0m", end="\n\n")
        concat_message = str(id_number)
        print("\u001b[35;1m(j) Hash of the message is calculated: \u001b[0m", end="\n\n")
        verification_hash = hashlib.sha256(concat_message.encode('utf-8')).hexdigest()
        verification_hash = int(verification_hash, 16)
        print("\u001b[33;1mHash(idNumber): \u001b[0m", verification_hash, end="\n\n")
        print("\u001b[35;1m(k) Decrypting the message(without Hash) using (digital_signature s)^(public key)mod n = (message_hash)^((private key)*(public key))mod n = (message_hash)^1 mod n = (message_hash): \u001b[0m", end='\n\n')
        decrypted_message = pow(s, public_key, n)
        print("\u001b[33;1mDecrypted Message: \u001b[0m", decrypted_message, end="\n\n")
        if decrypted_message == verification_hash:
            print("\u001b[32;1mVoter Authenticated\u001b[0m")

    @staticmethod
    def print_module_header(module_name):
        print('\n\n')
        for _ in range(100):
            print("-", end="")
        print()
        for _ in range(30):
            print(" ", end="")
        print(f"\u001b[31m {module_name} \u001b[0m")
        for _ in range(100):
            print("-", end="")
        print('\n\n')

    @staticmethod
    def ask_to_vote_again():
        print("\u001b[32;1mDo you want to vote again? (yes/no)\u001b[0m")
        vote_again = input().strip().lower()
        return vote_again == 'yes'


if __name__ == "__main__":
    pm = PollMachine()