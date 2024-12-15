import cryptomath
import random
import hashlib


# n has to be greater than m otherwise lossy message
class Signer:

    def __init__(self):
        self.public_key, self.private_key = self.generate_information()

    def generate_information(self):
        # Generates public and private keys
        p = cryptomath.find_prime()
        q = cryptomath.find_prime()
        phi = (p - 1) * (q - 1)
        n = p * q

        print('\n\n')
        for _ in range(40):
            print(" ", end="")
        print("\u001b[1mBlind Signatures and Voting Scheme (using RSA)\u001b[0m")
        for _ in range(100):
            print("-", end="")
        print()
        for _ in range(50):
            print(" ", end="")
        print("\u001b[31mMODULE 1\u001b[37m")
        for _ in range(100):
            print("-", end="")
        print('\n\n')

        print("\u001b[32;1m1. Signing Authority Creates Public and Private Information:\u001b[0m", end='\n\n')
        print("\u001b[35;1m(a) Generates random p and q\u001b[0m", end='\n\n')
        print("\u001b[33;1mp: \u001b[0m", p, end='\n\n')
        print("\u001b[33;1mq: \u001b[0m", q, end='\n\n')
        print("\u001b[35;1m(b) Computes n=p*q and ϕ(n)=(p-1)(q-1)\u001b[0m", end='\n\n')
        print("\u001b[33;1mn: \u001b[0m", n, end='\n\n')
        print("\u001b[33;1mϕ(n): \u001b[0m", phi, end='\n\n')

        print("\u001b[35;1m(c) Picks e such that gcd(ϕ(n),e)=1 & 1<e<ϕ(n):\u001b[0m", end='\n\n')

        found_encryption_key = False
        while not found_encryption_key:
            e = random.randint(2, phi - 1)
            if cryptomath.gcd(e, phi) == 1:
                found_encryption_key = True

        print("\u001b[33;1me: \u001b[0m", e, end='\n\n')

        print("\u001b[33;1mChecking whether gcd(e, ϕ)==1: \u001b[0m")
        print("\u001b[33;1mgcd\u001b[0m(", e, ",", phi, ")", '\n' , "=", "\u001b[33;1m", cryptomath.gcd(e, phi))
        v = False
        if cryptomath.gcd(e, phi) == 1:
            v = True
        print("Verification Status: ", v, "\u001b[0m", end='\n\n')
        print("\u001b[35;1m(d) Computes d, where d is the inverse of e modulo ϕ(n)\u001b[0m", end='\n\n')
        d = cryptomath.find_mod_inverse(e, phi)

        print("\u001b[33;1md: \u001b[0m", d, end='\n\n')

        print("\u001b[33;1mChecking whether e*d mod ϕ(n) is 1 (which is the required condition for d to be inverse of e mod ϕ(n)): \u001b[0m")
        print(e, "*", d, "mod", phi, '\n' ,"=", e * d % phi, end='\n')
        v = False
        if (e * d % phi) == 1:
            v = True
        print("\u001b[33;1mVerification Status: \u001b[0m", v, end='\n\n')

        print("\u001b[35;1m(e) Publishes to PUBLIC: (n,e) and the public and private keys calculated respectively are:\u001b[0m", end='\n\n')
        print("\u001b[33;1mPublic Key (n, e): \u001b[0m", "(", n, ", " , e, ")", end='\n\n')
        print("\u001b[33;1mPrivate Key (n, d):  \u001b[0m", "(", n, ", " , d, ")", end='\n\n')
        public_info = {"n": n, "e": e}
        private_info = {"n": n, "d": d}

        return [public_info, private_info]

    def get_public_key(self):
        return self.public_key

    def sign_message(self, message, eligible):
        print('\n\n')
        for _ in range(100):
            print("-", end="")
        print()
        for _ in range(50):
            print(" ", end="")
        print("\u001b[31mMODULE 3\u001b[37m")
        for _ in range(100):
            print("-", end="")
        print('\n\n')

        print("\u001b[32;1m3. Signing Authority Authorizes Ballot\u001b[0m", end='\n\n')
        print("\u001b[35;1m(a) Signing authority receives m'\u001b[0m", end='\n\n')
        print("\u001b[35;1m(b) Signing authority verifies whether voter is eligible to vote\u001b[0m", end='\n\n')
        if eligible == "y":
            print("\u001b[35;1m(c) If voter is eligible, signing authority signs ballot: sign = ((blinded message)^d)mod n = ((m* (r^e))^d) mod n = (m^d * r^(ed)) mod n = (m^d * r^1) mod n = (m^d * r) mod n(where d is the private key of the signing authority)\u001b[0m", end='\n\n')
            s = pow(message, self.private_key['d'], self.public_key['n'])  # important # ERR1
            print("\u001b[33;1mSign by Signing Authority: \u001b[0m", s, end='\n\n')
            return s
        return None

    def verify_voter(self, eligible):
        # This method is intentionally left empty
        pass


class Voter:

    def __init__(self, n, eligible):
        self.eligible = eligible

        print("\u001b[35;1m(d) Generates r such that r is a relative prime n and 2<= r <=(n-1)\u001b[0m", end='\n\n')
        found_r = False
        while not found_r:
            self.r = random.randint(2, n - 1)
            if cryptomath.gcd(self.r, n) == 1:
                print("\u001b[33;1mr: \u001b[0m", self.r, end='\n\n')
                found_r = True
        print("\u001b[33;1mChecking whether gcd(r, n)==1: \u001b[0m", end='\n\n')
        print("\u001b[33;1mgcd \u001b[0m", "(", self.r, ",", n, ")", '\n' , "=", "\u001b[33;1m", cryptomath.gcd(self.r, n), end='\n\n')
        v = False
        if cryptomath.gcd(self.r, n) == 1:
            v = True
        print("Verification Status: ", v, "\u001b[0m", end='\n\n')

    def unwrap_signature(self, signed_blind_message, n):
        print('\n\n')
        for _ in range(100):
            print("-", end="")
        print()
        for _ in range(50):
            print(" ", end="")
        print("\u001b[31mMODULE 4\u001b[37m")
        for _ in range(100):
            print("-", end="")
        print('\n\n')
        print("\u001b[32;1m4. Voter Unwraps Blinding of Ballot\u001b[0m", end='\n\n')
        print("\u001b[35;1m(a) Receives s'\u001b[0m", end='\n\n')

        print("\u001b[35;1m(g) Computes r_inv, where r_inv is the inverse of r modulo n. r will be used by voter to unwrap the blinded message.\u001b[0m", end='\n\n')
        r_inv = cryptomath.find_mod_inverse(self.r, n)  # ERR3
        print("r_inv: ", r_inv)

        print()
        print("\u001b[33;1mChecking whether r * r_inv mod n is 1 (which is the required condition for r_inv to be inverse of r mod n): \u001b[0m")
        print(self.r, "*", r_inv, "mod", n, '\n' ,"=", self.r * r_inv % n, end='\n')
        v = False
        if self.r * r_inv % n == 1:
            v = True
        print("\u001b[33;1mVerification Status: \u001b[0m", v, end='\n\n')
        print("\u001b[35;1m(b) Computes s = (s')*(r_inv) mod n = (m^d * r)*(r_inv) mod n = (m^d * 1) mod n = (m^d) mod n \u001b[0m", end='\n\n')
        s = (signed_blind_message * r_inv) % n
        print("\u001b[33;1mSigned message, s: \u001b[0m", s, end='\n\n')
        print("\u001b[35;1m(c) Sends the signature s in to the ballot receiving location\u001b[0m", end='\n\n')
        return s

    def blind_message(self, m, n, e):
        print("\u001b[35;1m(e) Computes blinded message (disguises his message): m' = (m* (r^e)) mod n (where n and e are public knowledge)\u001b[0m", end='\n\n')
        blind_message = (m * pow(self.r, e, n)) % n  # returns r to the power of e, modulus n.
        print("\u001b[33;1mBlind Message: \u001b[0m", blind_message)
        return blind_message

    def get_eligibility(self):
        return self.eligible


def verify_signature(message, rand_num, signature, public_e, public_n):
    ballot = pow(signature, public_e, public_n)  # decrypting, it gets back the message_hash
    verification_status = (int(hashlib.sha256((str(message) + str(rand_num)).encode('utf-8')).hexdigest(), 16) == ballot)
    print("\u001b[35;1mThe encrypted/signed hash message is decrypted with the signed authority's public key (s^e) mod n = (m^d)^e mod n = (m^1) mod n = m mod n = m : \u001b[0m", "\n", ballot, end="\n\n")
    print("\u001b[35;1mCalculate the hash of the concatenated message as hash(concatenated message): \n \u001b[0m", int(hashlib.sha256((str(message) + str(rand_num)).encode('utf-8')).hexdigest(), 16), end='\n\n')
    print("\u001b[31mIf above 2 values are equal then it is established that the message has indeed been approved by the signing authority. \u001b[0m", end='\n\n')
    decoded_message = message
    return verification_status, decoded_message
