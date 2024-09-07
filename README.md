#Opis
Jednostavan alat za upravljanje lozinkama koji koristi simetričnu kriptografiju za sigurno spremanje i dohvaćanje lozinki.


#Instalacija
  1. Preuzmite symmetric_cryptography.py
  2. Instalirajte pycryptodome biblioteku (pip install pycryptodome)


#Pokretanje
Pokretanje je preko command prompta ovim komandama :
  1. python symmetric_cryptography.py init <MasterPassword> -> Ovdje postavljate master password koju jedino moramo zapamtit i s njom sve spremamo i dohvaćamo
     Napomena : Master password mora biti najmanje 8 znakova dug i sadržavat jedan broj i jedan znak.
  2. python symmetric_cryptography.py put <MasterPassword> <stranica> <lozinka> -> Pod stranica se misli npr. "www.youtube.com"
  3. python symmetric_cryptography.py get <MasterPassword> <stranica> -> dohvaćanje šifre za određenu stranicu


Ovim alatom osiguravamo da se pamti samo jedna lozinka i to je master passwor i s lakoćom dolazimo do šifre od neke stranice koja nam treba.
Sve lozinke se čuvaju u datoteci "datoteka.txt" u kojoj su podatci kriptirani.
