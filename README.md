# ToppsEncryptionMethod
Using the concepts of TDES, I have made a way to further expand AES and TDES's Lifespan

Introduction:
This Method using both the TDES and AES algorithm to produce an interesting way to extend key length
as well as make it harder to guess the key.

CTEM:
The CTEM method stands for Continuous Topps Encryption Method and it works be essentially encrypting twice.
The interesting thing though is that the intial encryption key' IV can be used to expand the key space due the fact it can be random.
The second key's IV would need to be known though.
To futher frustrate the proccess of guessing the key, the sixteen possible pairings of AES-128, AES-192, AES-256, and TDES are selected at random. 
This also creates a problem for attackers as if they guess the wrong pairing then even a brute force attack on that particular pairing type would never work.

CTEM Process:
Key Selection:
Key1 -> Random choice of AES-128, AES-192, AES-256, or TDES generation
IV1 -> Randomly generated
Key2 -> Random choice of AES-128, AES-192, AES-256, or TDES generation

Key Structure:
Length of Key1 in bytes (single byte) + Key1, Length of Key2 in bytes(single byte) + Key2, IV2

Encryption:
Plaintext -> Encrypted with Key1, IV1 -> Ciphertext1
IV1(in front) + Ciphertext2 -> Ciphertext2
Ciphertext2 -> Encrypted with Key2, IV2 -> Final Ciphertext

Decryption:
Read in Key1, Key2, IV2
Final Ciphertext -> Decrypted with Key2, IV2 -> IV1(in front) + Ciphertext1
Read in IV1 from infront of Ciphertext1, then Amend Message
Ciphertext1 -> Decrypt with Key1, IV1 -> Plaintext

NOTES for CTEM:
TDES has an extra parity byte due the fact that both AES-192 and TDES have same key length of 24 bytes(192-bit)
The exta parity bit also allow for determination of whether IV should be 64-bit(TDES) or 128-bit(AES)

OTEM:
OTEM stands for One-time Topps Encryption Method and is a more useless but more secure version of CTEM(My attempt of a One-Time Pad).
It builds off CTEM which is described above so read that before reading this(Trust me you'll probably be lost...).
Ok lets get started then:
OTEM doesn't use a seperate Keygen function like CTEM and creates a new key everytime.
The key is basically a CTEM key with the added variables of Embedded Bytes, Embedded Interval, and Total Markers.
Ok I know what are those...
The way OTEM works is that it embeds two random bytes(a character) within Ciphertext1 at a randomly selected interval based on message length. 
So if the message length is 12 and the interval is 11. 
Every 11th character two bytes(character) are inserted.
To support the interval the message is padded.
Therefore four total embedded bytes are inserted or two charcters.
Ok lets look at a quick example before you complain your head hurts.

EX:
"My dog loves you" The message between the "" is 16 characters (Yes I actaully counted...)
Lets chose the two embedded btyes to be an "E" charcter. (You choose whatever the encoding you want, I used UTF-8)
Also lets make the embedded interval to be 10.

So lets just say that when "My dog loves you." is encrypted first and somehow comes out to be "My cat hates you"
The next step would be to embed the character E every 10 characters.
The result is "My cat hatEes you    E"
This is then encrypted with the second key like CTEM.

OTEM Process:
Key Selection:
Pre-Encryption:
Key1 -> Random choice of AES-128, AES-192, AES-256, or TDES generation
IV1 -> Randomly generated
Key2 -> Random choice of AES-128, AES-192, AES-256, or TDES generation
During Encryption:
Embedded Bytes -> Two bytes randomly Selected
Embedded Interval -> Random int up to either int32 maximum or message length
Total Markers -> Total amount of Embedded bytes embedded in Encryption process

Encryption:
Plaintext -> Encrypted with Key1, IV1 -> Ciphertext1
Ciphertext1 -> Embed Bytes at random interval(Count all the bytes embedded) -> Embedded Chiphertext1
Embedded Chiphertext1 -> Encrypted with Key2, IV2 -> Final Ciphertext

Decryption:
Read in Key1, IV1, Key2, IV2, Embedded Bytes, Embedded Interval, Total Markers (Yes the key is that order)
Final Ciphertext -> Decrypted with Key2, IV2 -> Embedded Ciphertext1
Embedded Ciphertext1 -> Search for Embedded bytes until all are found -> Amend Ciphertext1 to pre-embedded form
Ciphertext1 -> Decrypt with Key1, IV1 -> Plaintext

NOTES for OTEM:
TDES has an extra parity byte due the fact that both AES-192 and TDES have same key length of 24 bytes(192-bit)
The exta parity bit also allow for determination of whether IV should be 64-bit(TDES) or 128-bit(AES)

C# Class:
I have made a little example solution with a class that contains both methods and their member functions
PUBLIC:
byte[] CTEMKey;
byte[] OTEMKey;
public void CTEM_KeyGen()
public void CTEM_Encrypt(string MessageLocation, string OutputFile)
public void CTEM_Decrypt(string MessageLocation, string OutputFile)
public void OTEM_Encrypt(string Message_Location, string OutputFile)
public void OTEM_Decrypt(string MessageLocation, string OutputFileLocation)

PRIVATE:
private byte[] Encrypt(byte[] Data, byte[] key, byte[] IV, int Type, int mode) Used for AES/TDES encryption
private byte[] Decrypt(byte[] Data, byte[] key, byte[] IV, int Type, int mode) Used for AES/TDES decryption

NOTES about C# demo:
Demo is limited to data sizes of a byte array in Visual Studio(approx 2GB).
CTEM's and OTEM's encrypt should be modified to read in chunks of the data to encrypt if the implmentation is to be used with larger files.
I will get around to commenting the code for OTEM when i get a chance.
