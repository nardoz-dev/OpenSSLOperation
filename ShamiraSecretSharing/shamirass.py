import random

# Define the secret and the pair (n,k)
def define_secret_and_parameters(secret, n, k):
    return secret, n, k

# Generate the polynomial coefficients
def generate_fragments(secret, n, k):
    coefficients = [secret] + [random.randint(0, secret) for i in range(k-1)]

    # Generate the fragments
    fragments = []
    for i in range(1, n+1):
        fragment = (i, sum(coefficient * i**exponent for exponent, coefficient in enumerate(coefficients)))
        fragments.append(fragment)

    return fragments

# Reconstruct the secret using Lagrange interpolation
def reconstruct_secret(fragments, k):
    secret = 0
    for i, fragment in enumerate(fragments[:k]):
        xi, yi = fragment
        secret += yi * product(xj/(xj - xi) for j, (xj, _) in enumerate(fragments[:k]) if i != j)
    return secret

# Helper function to compute the product of a list of numbers
def product(iterable):
    result = 1
    for x in iterable:
        result *= x
    return result

# Define the secret and the pair (n,k)
secret, n, k = define_secret_and_parameters(12345, 7, 4)

# Generate the fragments
fragments = generate_fragments(secret, n, k)
print(f"Generated fragments: {fragments}")

# Reconstruct the secret using 3 fragments
reconstructed_secret = reconstruct_secret(fragments[:4], 4)
print(f"Reconstructed secret using 4 fragments: {reconstructed_secret}")

# Reconstruct the secret using 4 fragments
reconstructed_secret = reconstruct_secret(fragments[:5], 5)
print(f"Reconstructed secret using 5 fragments: {reconstructed_secret}")

# Reconstruct the secret using 2 fragments (should fail)
reconstructed_secret = reconstruct_secret(fragments[:3], 3)
print(f"Reconstructed secret using less fragments (should fail) : {reconstructed_secret}")
