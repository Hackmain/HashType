import hashlib

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

original_text = "follow me in insta esefkh740_"
md5_result = md5_hash(original_text)
print(f"MD5 hash of '{original_text}': {md5_result}")

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

original_text = "follow me in insta esefkh740_"
sha256_result = sha256_hash(original_text)
print(f"SHA-256 hash of '{original_text}': {sha256_result}")

def sha512_hash(text):
    return hashlib.sha512(text.encode()).hexdigest()

original_text = "follow me in insta esefkh740_"
sha512_result = sha512_hash(original_text)
print(f"SHA-512 hash of '{original_text}': {sha512_result}")
