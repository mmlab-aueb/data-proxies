import sys
import json 
import base64
import hashlib
from jwcrypto import jwk, jws
from secrets import token_bytes
from cryptography.hazmat.primitives import serialization
import random
import time
import os

try:
    with open("ec_private.pem", "rb") as f:
        private_pem = f.read()
    # Create JWK from PEM
    key = jwk.JWK.from_pem(private_pem)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

def _get_disclosures(json_object, disclosures, prefix):
    if isinstance(json_object, dict):
        for key, value in json_object.items():
            claim =  prefix + "/" + key
            disclosures.append([claim,value])
            if isinstance(value, dict) or isinstance(value, list):
                _get_disclosures(value, disclosures, claim)
    elif isinstance(json_object, list):
        for key in range(len(json_object)):
            claim =  prefix + "/" + str(key)
            value = json_object[key]
            disclosures.append([claim,value])
            if isinstance(value, dict) or isinstance(value, list):
                _get_disclosures(value, disclosures, claim)
    return disclosures
    

def disclosures(json_object):
    claims = _get_disclosures(json_object, [], "")
    return claims

def sign(json_str):
    try:
        # Decode base64 to JSON string
        # Parse JSON
        json_object = json.loads(json_str)
        
        all_disclosures = disclosures(json_object)
        proof_object = []
        for item in all_disclosures:
            salt = base64.b64encode(token_bytes(16)).decode()
            item.append(salt)
            disclosure_sha256 = hashlib.sha256()
            disclosure_sha256.update(json.dumps(item).encode('utf-8'))
            proof_object.append(base64.b64encode(disclosure_sha256.digest()).decode())

        proof = jws.JWS(json.dumps(proof_object).encode('utf-8'))
        proof.add_signature(key, None,{"alg": "ES256"})
        object_signature= proof.serialize(compact=True)
        header, _, signature = object_signature.split('.')
        return(base64.b64encode(json.dumps(all_disclosures).encode()).decode(),header+".."+signature)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def main():
    # Folder containing the JSON files
    folder_path = './objects'

    # Get list of JSON files in the folder
    files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    assert len(files) >= 100, "Not enough JSON files in ./objects folder."

    # Sample 100 random files
    selected_files = random.sample(files, 100)

    # List to store timing results
    timings = []

    # Process each selected file
    for filename in selected_files:
        with open(os.path.join(folder_path, filename), 'r') as f:
            json_str = f.read()
        
        start_time = time.perf_counter()
        disclosures,signature = sign(json_str)
        end_time = time.perf_counter()
        elapsed_ms = (end_time - start_time) * 1000  # convert to milliseconds
        timings.append(elapsed_ms)
        with open(f'./signatures/{filename}', 'w') as f:
            f.write(disclosures + "\n")
            f.write(signature + "\n")

    # Calculate statistics
    min_time = min(timings)
    max_time = max(timings)
    avg_time = sum(timings) / len(timings)

    # Output results
    print(f"Min time: {min_time:.3f} ms")
    print(f"Max time: {max_time:.3f} ms")
    print(f"Average time: {avg_time:.3f} ms")
    

if __name__ == "__main__":
    main()