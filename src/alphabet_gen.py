def generate(alphabet, max_len):
    if max_len <= 0: return
    for c in alphabet:
        yield c
    for c in alphabet:
        for next in generate(alphabet, max_len-1):
            yield c + next

alpha1 = "10"
words1 = list(generate(alpha1,2))
expected1 = ["1","0","00","01","10","11"]
words1.sort()
expected1.sort()
if words1 == expected1:
    print("[PASS]")
else:
    print("[FAIL]")
    
alpha2a = "abc"
words2a = list(generate(alpha2a,4))
alpha2b = "cba"
words2b = list(generate(alpha2b,4))
words2a.sort()
words2b.sort()
if words2a == words2b:
    print("[PASS]")
else:
    print("[FAIL]")
    