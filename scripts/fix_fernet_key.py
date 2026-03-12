import os
from cryptography.fernet import Fernet

env_path = '/var/www/Forensic_CPA_AI/.env'

with open(env_path, 'r') as f:
    lines = f.readlines()

key = Fernet.generate_key().decode('utf-8')
found = False

for i, line in enumerate(lines):
    if line.startswith('OAUTH_ENCRYPTION_KEY='):
        lines[i] = f'OAUTH_ENCRYPTION_KEY={key}\n'
        found = True
        break

if not found:
    lines.append(f'\nOAUTH_ENCRYPTION_KEY={key}\n')

with open(env_path, 'w') as f:
    f.writelines(lines)

print("Fixed OAUTH_ENCRYPTION_KEY")
