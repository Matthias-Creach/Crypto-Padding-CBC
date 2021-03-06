'''
 
Serveur d'attaque: http://padding-oracle.cleverapps.io/
Doc:               https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

'''

import requests
import base64
import time


'''
Tentative de connection au serveur en envoyant le paquet de 16octets

@params
b64       -> arraybytes[16] -> Le tableau de 16 octets encoder en b64
tentative -> int            -> Nombre de fois que l'on va tenter de se connecter au serveur distant avant d'arreter

@return
res.text  -> str            -> "0" ou "1" si le serveur valide ou non le padding

'''
def connection_server(b64, tentative):
	try:
		res = requests.post("http://padding-oracle.cleverapps.io/", data=b64)
		return res.text

	except requests.exceptions.ConnectionError as error:
		if tentative < 20:
			time.sleep(2)
			return connection_server(b64, tentative+1)
		else:
			raise error

'''
Algorithme de brute force qui va permettre de trouver le plaintext à partir du ciphertext

@params
start_time -> int         -> Temps à partir duquel l'algo est lancé, qui permettra d'avoir le temps total d'execution  

@return
P          -> bytearray[] -> Le plaintext encode en 'utf-8'

'''
def padding_cbc_attack(start_time):
	CIPHER = bytearray.fromhex('0eb32a58142e7af30b73ddada9412ed12ff7b13c8df1916ec18c9595f561a2ea486bb1d91033d3bf63c501972cf8d09440b1b9b2210d02cc429c537a70418de1a1e2e6d26ea5ed4f1c9c1d30790a7ac09c2a3367548dfcd146d825c052b108fdd0a672fe4b89a5084a4eab61fdb12f8e47b79b12b1acc9482447d303dd57acb9b68bff1ca6ab41f13bfeb4a430455195d3f81b85601d96abb3cc7f4ee1debb914a1764877ab4b4f7dfd5e108a0bba818d076ee75b40485e9cee8a0e9579803ba02843521ea3de680391d406913741ec329c1506c7cb94c54a1d79e7fa505b8af0750e688e03820c326e8aa51157c021722f7e22f8d733f24dece8e4d21b876ecb18773842c635b1ea78361e193133b955169c80ee3a57f1d6d49a939ee9f93ba2b1a137cbc5aa63e68f284cf530ed55556e747305327d51ae682ed06720cdb49c1d3df741fc8aa774bab6defcfbf30ff5e47de0a61b1e6d0b85ee9907942e66a9d5fc2aea99cfe0782d3d766a630c4809767d237c0d583271f4ea1d11a7574da3b025c03cb671441e2d50cbff89923622d74224acf59b8fe09f0edc24b1735253242bd44b982309f7ab7d153e19506a02f5e5387e4523dbd200ef1e7c9ef01c72d0f3271201d8fe69863173b2f009ebd2b16e08f55830f21d99ff6877b001305a6d0fab3150ef10eba12d1e00bae1b99f3e702dd9c04c5c47e6ce6c196886e52e7d5cb8f8921568c32eac7967406ab48')

	Ci = bytearray.fromhex('0000000000000000')	# block CipherText précédent, on commence avec un bloc à 0
	P  = bytearray()							# PlainText complet 
	
	#On parcout la chaine du CipherText, elle est découpé en bloc de 8
	for block in range(0, len(CIPHER), 8):
		C  = CIPHER[block:block+8]					# block CipherText en cours
		X  = bytearray.fromhex('0000000000000000')  # block Custom
		Pi = bytearray()							# PlainText correspondant au bloc en cours

		#On parcourt les 8 octets en partant du dernier (de 7 à 0)
		for o in range(7, -1, -1):
			
			#Un peu de log pour avoir des informations
			print("\nBlock " + str(int(block/8+1))  + "/"+ str(int(len(CIPHER)/8)) +" - Octet " + str(o))
			print("--- %s mn %s s---" % (int((time.time() - start_time)/60), int((time.time() - start_time)%60)))
			
			padding = 8 - o
			#On va incrémenter l'octet en question jusqu'à que le serveur renvoie la valeur "1" pour confirmer que le padding lui convient
			for v in range(0, 255):

				X_tmp = bytearray.fromhex('0000000000000000')

				#On applique le padding sur les octets souhaités
				for i in range(0, padding):
					if(7-i != o):
						X_tmp[7-i] = X[7-i] ^ padding
					else:
						X_tmp[7-i] = X[7-i] ^ padding ^ v

				#On concatène notre bloc custom X_tmp et notre CipherText C, puis on l'envoie au serveur
				D  = X_tmp + C
				if(len(D) == 16):
					b64 = base64.standard_b64encode(D)
					r = connection_server(b64, 0)
				else:
					print("Erreur - La taille du tableau envoyé est incorrect : " + str(len(D)))
					return

				if(r == "1"):
					X[o] = v
					#Pour obtenir le plaintext, on se doit de Xor avec le block CipherText précédent
					Pi.insert(0, v ^ Ci[o])
					print(Pi)
					break

		#On ajoute notre block Pi à notre P
		P += Pi

		Ci = CIPHER[block:block+8]	#MAJ du CipherText précedent avec le block actuel
		
	return P

if __name__ == "__main__":
    print("Lancement de l'attaque CBC padding oracle")

    start_time = time.time()
    plaintext = padding_cbc_attack(start_time)

    print("--- Fin de l'attaque --- ")
    print("--- Temps d'exécution total: %s mn %s s---" % (int((time.time() - start_time)/60), int((time.time() - start_time)%60)))
    print("--- PlainText: ")
    print(plaintext.decode('utf-8'))
