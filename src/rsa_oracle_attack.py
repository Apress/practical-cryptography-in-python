import time, sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import gmpy2
from collections import namedtuple

Interval = namedtuple('Interval', ['a','b']) 
# Imports and dependencies for RSA Oracle Attack
# Dependencies: simple_rsa_encrypt(), simple_rsa_decypt()
#               bytes_to_int()

#### DANGER ####
# The following RSA encryption and decryption is 
# completely unsafe and terribly broken. DO NOT USE
# for anything other than the practice exercise
################  
def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)
#### DANGER ####
    
# RSA Oracle Attack Component 
def int_to_bytes(i, min_size=None):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    b = i.to_bytes((i.bit_length()+7)//8, byteorder='big')
    if min_size != None and len(b) < min_size:
        b = b'\x00'*(min_size-len(b)) + b
    return b
    
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')
    
class RSAStat:
    def __init__(self):
        self.i = 0
        self.runtime = 0.0
        self.search_count = 0

# RSA Oracle Attack Component        
class FakeOracle:
    def __init__(self, private_key):
        self.private_key = private_key
        
    def __call__(self, cipher_text):
        recovered_as_int = simple_rsa_decrypt(cipher_text, self.private_key)
        recovered = int_to_bytes(recovered_as_int, self.private_key.key_size//8)
        return recovered[0:2] == bytes([0, 2])

class RSAOracleAttacker:
    def __init__(self, public_key, oracle):
        self.public_key = public_key
        self.oracle = oracle
        self.stats = []
    
    def _step1_blinding(self, c):
        self.c0 = c
        
        self.B = 2**(self.public_key.key_size-16)
        self.s = [1]
        self.M = [ [Interval(2*self.B, (3*self.B)-1)] ]
        
        self.i = 1
        self.n = self.public_key.public_numbers().n

# RSA Oracle Attack Component, part of class RSAOracleAttacker
    def _find_s(self, start_s, s_max=None):
        self.stats[-1].search_count += 1
        si = start_s
        ci = simple_rsa_encrypt(si, self.public_key)
        while not self.oracle((self.c0 * ci) % self.n):
            si += 1
            if s_max and (si > s_max):
                return None
            ci = simple_rsa_encrypt(si, self.public_key)
        return si

# RSA Oracle Attack Component, part of class RSAOracleAttacker 
    def _step2a_start_the_searching(self):
        si = self._find_s(start_s=gmpy2.c_div(self.n, 3*self.B))
        return si
        
# RSA Oracle Attack Component, part of class RSAOracleAttacker
    def _step2b_searching_with_more_than_one_interval(self):
        si = self._find_s(start_s=self.s[-1]+1)
        return si

# RSA Oracle Attack Component, part of class RSAOracleAttacker 
    def _step2c_searching_with_one_interval_left(self):
        a,b = self.M[-1][0]
        ri = gmpy2.c_div(2*(b*self.s[-1] - 2*self.B),self.n)
        si = None
    
        while si == None:
            si = gmpy2.c_div((2*self.B+ri*self.n),b)
            
            s_max = gmpy2.c_div((3*self.B+ri*self.n),a) 
            si = self._find_s(start_s=si, s_max=s_max)
            ri += 1
        return si

# RSA Oracle Attack Component, part of class RSAOracleAttacker
    def _step3_narrowing_set_of_solutions(self, si):
        new_intervals = set()
        for a,b in self.M[-1]:
            r_min = gmpy2.c_div((a*si - 3*self.B + 1),self.n)
            r_max = gmpy2.f_div((b*si - 2*self.B),self.n)

            for r in range(r_min, r_max+1):
                a_candidate = gmpy2.c_div((2*self.B+r*self.n),si)
                b_candidate = gmpy2.f_div((3*self.B-1+r*self.n),si)

                new_interval = Interval(max(a, a_candidate), min(b,b_candidate))
                new_intervals.add(new_interval)
        new_intervals = list(new_intervals)
        self.M.append(new_intervals)
        self.s.append(si)
        
        if len(new_intervals) == 1 and new_intervals[0].a == new_intervals[0].b:
            return True
        return False
        
# RSA Oracle Attack Component, part of class RSAOracleAttacker
    def _step4_computing_the_solution(self):
        interval = self.M[-1][0]
        return interval.a

# RSA Oracle Attack Component, part of class RSAOracleAttacker
    def attack(self, c):
        self.stats.append(RSAStat())
        t0 = time.time()
        self._step1_blinding(c)
        
        # do this until there is one interval left
        finished = False
        while not finished:
            if self.i == 1:
                si = self._step2a_start_the_searching()
            elif len(self.M[-1]) > 1:
                si = self._step2b_searching_with_more_than_one_interval()
            elif len(self.M[-1]) == 1:
                interval = self.M[-1][0]
                si = self._step2c_searching_with_one_interval_left()

            print("Found! i={} si={}".format(self.i, si))
            finished = self._step3_narrowing_set_of_solutions(si)
            self.i += 1

        print("Found solution")
        m = self._step4_computing_the_solution()
        
        tn = time.time()
        self.stats[-1].i = self.i
        self.stats[-1].runtime = tn - t0
        return m
            
def main(args):
    key_size, messagecount = [int(arg) for arg in args]
    print("Running {} tests with key size {}".format(messagecount, key_size))
    
    private_key = rsa.generate_private_key(
              public_exponent=65537,
              key_size=key_size,
              backend=default_backend()
          )
    public_key = private_key.public_key()
    
    oracle = FakeOracle(private_key)
    attack_program = RSAOracleAttacker(public_key, oracle)
    
    for i in range(messagecount):
        message = b'test %d' % (i)
    
        ###
        # WARNING: PKCS #1 v1.5 is obsolete and has vulnerabilities
        # DO NOT USE EXCEPT WITH LEGACY PROTOCOLS
        ciphertext = public_key.encrypt(
            message,
            padding.PKCS1v15()
        )
        ciphertext_as_int = bytes_to_int(ciphertext)
    
        print("\nWe're starting our attack run on message {}.".format(i))
    
        recovered_as_int = attack_program.attack(ciphertext_as_int)
        if int_to_bytes(recovered_as_int).endswith(message):
            print("[PASS]")
        else:
            print(int_to_bytes(recovered_as_int))
            print("[FAIL]")
            return
        print("\tRecovered: ", int_to_bytes(recovered_as_int))
    
    i_total = 0
    search_total = 0
    runtime_total = 0.0
    print(     "\nSTATISTICS")
    print(     "-------------------------")
    print(     "{:6} {:10} {:10} {:10}".format(
        "Test", "Iterations", "Searches", "Runtime"))
    print(     "-------------------------")
    for test_index in range(messagecount):
        test_stat = attack_program.stats[test_index]
        print("{:4} {:10} {:10} {:10}".format(
            test_index, 
            test_stat.i, test_stat.search_count, test_stat.runtime))
        i_total += test_stat.i
        search_total += test_stat.search_count
        runtime_total += test_stat.runtime
    i_avg = i_total/messagecount
    search_avg = search_total/messagecount
    runtime_avg = runtime_total/messagecount
    print("\n")
    print(     "AVERAGE:")
    print(     "{:6} {:10} {:10} {}".format(
        "", i_avg, search_avg, runtime_avg))
    
    
if __name__=="__main__":
    global recovered
    recovered = False
    main([512,1])
    sys.exit(0)
    main(sys.argv[1:])