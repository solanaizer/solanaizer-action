prompt = """
The following Solana smart contract written in Rust may have either no vulnerabilities or one of the following vulnerabilities:

{}

1. Integer overflow.
2  Integer underflow.
3. Unsafe memory.
4. Incorrect execution of authorization.
5. Depth of cross-contract call over four.
6. Reentrancy attack.
7. Errors in logic and arithmetic.
8. Computational units limit.

Return the number of the vulnerability found, or 0 if there is no vulnerability. 
"""
