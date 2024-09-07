import sys
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA512
from Crypto.Cipher import AES
import re
lista = {}

def enkripcija(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def dekripcija(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError:
        return None

def passwordCheck(lozinka) :

    if not len(lozinka) > 7 :
        return False
    if not re.search(r'[a-z]', lozinka) or not re.search(r'[A-Z]', lozinka) or not re.search(r'\d', lozinka):
        return False
    
    if not re.search(r'[!"#$%&/()=?*|<>;.,_-]', lozinka) :
        return False
    
    return True


def savePassword(address, sifraOdAdrese, masterPassword):
    

    with open("datoteka.txt", "rb") as file :
      encrypted_password = file.read()
    
    salt = encrypted_password[:16]
    
    storedKey = generateKey(masterPassword, salt)
    
    
    decrypted_password = dekripcija(encrypted_password[16:], storedKey)
    
    
    
    if decrypted_password  :
      decryptedTextDekodiran = decrypted_password.decode()
      decryptedTextDekodiranSplitan = decryptedTextDekodiran.splitlines()
      
      updatedLines = []
      pronadenaAdresa = False
      for line in decryptedTextDekodiranSplitan:
        if address in line :
          updatedLines.append(f"{address} {sifraOdAdrese}")
          pronadenaAdresa = True
          
        else :
          updatedLines.append(line)
      if not pronadenaAdresa :
        updatedLines.append(f"{address} {sifraOdAdrese}")


      noviTekst = '\n'.join(updatedLines)
      salt = generateSalt()
      noviKljuc = generateKey(masterPassword, salt)
      
      encrypted_data = enkripcija(noviTekst.encode(), noviKljuc)

      with open ("datoteka.txt", "wb") as file :
          file.write(salt + encrypted_data)
      print("Stored password for " + address + ".")
    else :
      print("Master password incorrect or integritiy check failed.")

  


      
def pronadiSifru(address, masterPassword) :
  with open("datoteka.txt", "rb") as file :
    lines = file.read()
  

  salt = lines[:16]
  storaniKey = generateKey(masterPassword, salt)
  dekriptiraneLinije = dekripcija(lines[16:], storaniKey)
  
  if dekriptiraneLinije:
    dekriptiraneLinijeDekodirano = dekriptiraneLinije.decode()
    dekodiraneLinijeSplitano = dekriptiraneLinijeDekodirano.splitlines()

    for line in dekodiraneLinijeSplitano[1:] :
      adresaLinije, sifraLinije = line.split()

      if adresaLinije == address :
        noviTekst = '\n'.join(dekodiraneLinijeSplitano)
        salt = generateSalt()
        noviKljuc = generateKey(masterPassword, salt)
        enkripcijaNovogTeksta = enkripcija(noviTekst.encode(), noviKljuc)
        with open("datoteka.txt", "wb") as file:
          file.write(salt + enkripcijaNovogTeksta)
        return sifraLinije
    
  
  else :
    print("Master password incorrect or integrity check failed.")

def generateKey(masterPassword, salt) :
  keys = PBKDF2(masterPassword, salt, 32, count=1000000, hmac_hash_module=SHA512)
  return keys


def generateSalt() :
   return get_random_bytes(16)

def generateIV() :
   return get_random_bytes(16)





argumenti = sys.argv



if argumenti.__contains__("init") :
  
  if len(argumenti) < 3 :
    print("Nedovoljan broj argumenata.")
  else :
    master_password = sys.argv[2]
    checkPassword = passwordCheck(master_password)
    if checkPassword :
        salt = generateSalt()
        key = generateKey(master_password, salt)
        stringProvjera = "ProvjeriOvoOvako"
        with open("datoteka.txt", "wb") as file:
            file.write(salt + enkripcija(stringProvjera.encode(), key))
      

        print("Password manager initialized.")
    else :
        print("Passwords must contain at least 8 characters, including uppercase and lowercase letters, a number, and a special character.")

elif argumenti.__contains__("get"):
  if len(argumenti) < 4 :
    print("Nedovoljan broj argumenata.")
  else :
    address = argumenti[3]
    master_password = argumenti[2]

    sifraAdrese = pronadiSifru(address, master_password)
    if sifraAdrese :
      print("Password for " + address + " is: " + sifraAdrese)
    else :
      print("Master password incorrect or integrity check failed.")
    


elif argumenti.__contains__("put"):
  if len(argumenti) < 5 :
    print("Nedovoljan broj argumenata.")
  else :
    address = argumenti[3]
    sifraOdAdrese = argumenti[4]
    master_password = argumenti[2]
    savePassword(address, sifraOdAdrese, master_password)
    
else :
  print("Pogresan unos podataka!")