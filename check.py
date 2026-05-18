import json 
f = open('encoder_mappings.json') 
enc = json.load(f) 
print(json.dumps(enc, indent=2)) 
