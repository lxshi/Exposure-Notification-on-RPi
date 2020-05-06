import cryptolib

metadata = bytes.fromhex('400C0000')

# Get Temporary Exposure Key
tek, i = cryptolib.getTEK(16)
print('\nTemporary Exposure Key:', tek)
print('Time i:', i)
print('TEK length:', len(tek), '\n')

# Get Rolling Proximity Identifier Key
rpik = cryptolib.getRPIK(tek)
print('Rolling Proximity Identifier Key:', rpik)
print('RPIK length:', len(rpik), '\n')

# Get Rolling Proximity Identifier
rpi = cryptolib.getRPI(rpik)
print('Rolling Proximity Identifier: ', rpi)
print('RPI length:', len(rpi), '\n')

# Get Associated Encrypted Metadata Key
aemk = cryptolib.getAEMK(tek)
print('Associated Encrypted Metadata Key: ', aemk)
print('AEMK len:', len(aemk), '\n')

# Get Associated Encrypted Metadata
aem = cryptolib.getAEM(aemk, rpi, metadata)
print('Associated Encrypted Metadata: ', aem)
print('AEM len:', len(aem), '\n')


'''
To identify any exposures, each client periodically fetches the list of new Diagnosis Keys 
from the Diagnosis Server. Because Diagnosis Keys are sets of Temporary Exposure Keys with 
their associated ENIntervalNumber i, each of the clients can again derive the sequence of 
Rolling Proximity Identifiers that were broadcast over Bluetooth from users who tested positive.

To do so, the clients use each of the Diagnosis Keys with the function defined, to derive the 
144 Rolling Proximity Identifiers starting from ENIntervalNumber i. The clients match each of 
the derived identifiers against the sequence they found through Bluetooth scanning. 
A +/- two-hour tolerance window is allowed between when a Rolling Proximity Identifier derived 
from the Diagnosis Key was supposed to be broadcast, and the time at which it was scanned.

The Associated Encrypted Metadata does not have to be decrypted until a match occurs. Upon 
decryption, the data has to be appropriately sanitized and validated as the Associated Encrypted 
Metadata isn’t authenticated.
'''

# Decrypt Metadata
metadata = cryptolib.getMetadata(aemk, rpi, aem)
print('Metadata: ', metadata)




