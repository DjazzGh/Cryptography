def encrypt_cesar(key,plain_text):
 
 cipher_text = ""

 for char in plain_text:
    if char.isalpha():  # Encrypt only alphabetic characters
      
       
        if char.islower():
            new_char = chr(((ord(char) - ord('a') + key) % 26) + ord('a'))
        elif char.isupper():
            new_char = chr(((ord(char) - ord('A') + key) % 26) + ord('A'))
        
       
        cipher_text += new_char
    else:
       
        cipher_text += char

 return cipher_text
 

def decrypt_cesar(key,cipher_text):
  
   plain_text=""
   for char in cipher_text:
    if char.isalpha():  # Encrypt only alphabetic characters
      
       
        if char.islower():
            new_char = chr(((ord(char) - ord('a') - key) % 26) + ord('a'))
        elif char.isupper():
            new_char = chr(((ord(char) - ord('A') - key) % 26) + ord('A'))
        
       
        plain_text += new_char
    else:
       
      plain_text += char
   return plain_text
