def encrypt_vigenere(key,plain_text):
 
 cipher_text=""
 i=0
 for char in plain_text:
    if char.isalpha():  # Encrypt only alphabetic characters
        shift = ord(key[i].lower()) - ord('a')
       
        if char.islower():
            new_char = chr(((ord(char) - ord('a') +shift ) % 26) + ord('a'))
           
           
                
        elif char.isupper():
            new_char = chr(((ord(char) - ord('A') +shift) % 26) + ord('A'))
           
        i+=1
        if i==len(key):
                i=0
        cipher_text += new_char
    else:
       
        cipher_text += char
 return cipher_text       
       

def decrypt_vigenere(key,cipher_text):
  
    plain_text=""
    i=0
    for char in cipher_text:
     if char.isalpha():  # Encrypt only alphabetic characters
        shift = ord(key[i].lower()) - ord('a')
       
        if char.islower():
            new_char = chr(((ord(char) - ord('a') -shift ) % 26) + ord('a'))
           
           
                
        elif char.isupper():
            new_char = chr(((ord(char) - ord('A') -shift) % 26) + ord('A'))
           
        i+=1
        if i==len(key):
                i=0
        plain_text += new_char
     else:
       
        plain_text += char
    return plain_text 
