import sys
import os
import json 
import base64
import hashlib
import random
from jwcrypto import jwk, jws
from secrets import token_bytes
from cryptography.hazmat.primitives import serialization
import time

with open("ec_public.pem", "rb") as f:
    public_pem = f.read()

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

def _set_claim(json_object, keys, value):
    key = keys[0]
    if key not in json_object:
        json_object[key]={}
    if (len(keys)==1):
        json_object[key]=value
    else:
        keys.pop(0)
        _set_claim(json_object[key], keys, value)
  

def json_object(disclosures):
    output = {}
    for disclosure in disclosures:
        if isinstance(disclosure, list):
            claim = disclosure[0]
            value = disclosure[1]
            keys = claim.split("/")
            keys.pop(0) # remove $
            _set_claim(output,keys,value)
    return output

def verify(base64JSON, signature):
    try:
        json_bytes = base64.b64decode(base64JSON)
        json_str = json_bytes.decode('utf-8')
        json_obj = json.loads(json_str)
        proof_object = []
        for item in json_obj:
            if isinstance(item, list):
                disclosure_sha256 = hashlib.sha256()
                disclosure_sha256.update(json.dumps(item).encode('utf-8'))
                proof_object.append(base64.b64encode(disclosure_sha256.digest()).decode())
            else:
                proof_object.append(item)

        # Create JWK from PEM
        key = jwk.JWK.from_pem(public_pem)
        claimed_proof = jws.JWS()
        claimed_proof.deserialize(signature)
        claimed_proof.verify(key, detached_payload=json.dumps(proof_object))
    except Exception as e:
        print(e)
        sys.exit(1)

def disclose(base64JSON, attributes):

    # Decode and parse the JSON object
    json_bytes = base64.b64decode(base64JSON)
    json_str = json_bytes.decode('utf-8')
    json_obj = json.loads(json_str)


    disclosed_items = random.sample(json_obj, attributes)
    values = [item[0] for item in disclosed_items]
    disclosures = []
    for item in json_obj:
        if not item[0] in values:
            disclosure_sha256 = hashlib.sha256()
            disclosure_sha256.update(json.dumps(item).encode('utf-8'))
            disclosures.append(base64.b64encode(disclosure_sha256.digest()).decode())
        else:
            disclosures.append(item)
    return (base64.b64encode(json.dumps(disclosures).encode()).decode())


def main():
    # Folder containing the JSON files
    folder_path = './signatures'

    # Get list of JSON files in the folder
    files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    for attributes in [5,10,15,20,25,30,35,40,45,50]:
        timings = []
        for filename in files:
            with open(os.path.join(folder_path, filename), 'r') as f:
                lines = f.readlines()
            base64JSON = lines[0].replace('\n', '')
            signature = lines[1].replace('\n', '')
            disclosed_item = disclose(base64JSON, attributes)
            start_time = time.perf_counter()
            verify(disclosed_item,signature)
            end_time = time.perf_counter()
            elapsed_ms = (end_time - start_time) * 1000  # convert to milliseconds
            timings.append(elapsed_ms)
        min_time = min(timings)
        max_time = max(timings)
        avg_time = sum(timings) / len(timings)

        # Output results
        print(f"Disclosed attributes: {attributes}")
        print(f"Min time: {min_time:.3f} ms")
        print(f"Max time: {max_time:.3f} ms")
        print(f"Average time: {avg_time:.3f} ms")
        print(f"{min_time:.3f} \t {max_time:.3f} \t {avg_time:.3f}")

    
    

if __name__ == "__main__":
    main()