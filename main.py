
import importlib
import random
import math
import AES
import Affine
import Cesar
import DES
import Diffie_Hellman
import Elgamal
import Hill_cipher
import Homomorphe_Elgamal
import IC
import Identification_Feige_Fiat_Shamir
import Identification_Schnorr
import otp
import playfair
import RC4
import RSA
import Shamir
import Signature_Elgamal
import Signature_RSA
import Standard_DSA
import substitution_aleatoire
import test_de_kasiski
import Vigenere
import tkinter as tk
from tkinter import ttk, messagebox
import importlib
import random
import math

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Interface")
        self.root.geometry("700x300")  
        self.root.resizable(False, False)  
        self.create_main_menu()

    def create_main_menu(self):
        
        tk.Button(self.root, text="Cryptographie classique", command=self.show_classique_menu).pack(pady=5)
        tk.Button(self.root, text="Cryptographie symetrique", command=self.show_symetrique_menu).pack(pady=5)
        tk.Button(self.root, text="Cryptographie asymetrique", command=self.show_asymetrique_menu).pack(pady=5)
        tk.Button(self.root, text="Hachage", command=self.show_hash_menu).pack(pady=5)
        tk.Button(self.root, text="Signature", command=self.show_signature_menu).pack(pady=5)
        tk.Button(self.root, text="Protocole", command=self.show_protocol_menu).pack(pady=5)






    def show_classique_menu(self):
        # Create a new window
        classique_window = tk.Toplevel(self.root)
        classique_window.title("Cryptographie Classique")
        classique_window.geometry("700x600")
        classique_window.resizable(False, False)  # Disable resizing

        # Dropdown menu for selecting cipher
        cipher_label = tk.Label(classique_window, text="Choisir un chiffrement:")
        cipher_label.pack(pady=5)

        cipher_var = tk.StringVar(classique_window)
        cipher_var.set("César")  # Default selection
        cipher_options = ["César", "Vigenère", "OTP", "Substitution aleatoire", "Affine", "Hill", "Playfair", "IC"]
        cipher_menu = ttk.OptionMenu(classique_window, cipher_var, cipher_var.get(), *cipher_options)
        cipher_menu.pack(pady=5)

        # Text entry field
        text_label = tk.Label(classique_window, text="Entrer le texte:")
        text_label.pack(pady=5)
        text_entry = tk.Entry(classique_window, width=40)
        text_entry.pack(pady=5)

        # Container for dynamic widgets
        param_frame = tk.Frame(classique_window)
        param_frame.pack(pady=5)
        button_frame = tk.Frame(classique_window)
        button_frame.pack(pady=5)

        # Parameter field widgets
        param_label = tk.Label(param_frame, text="Paramètre (clé/décalage):")
        param_entry = tk.Entry(param_frame, width=20)
        param2_label = tk.Label(param_frame, text="Deuxième paramètre (b):")
        param2_entry = tk.Entry(param_frame, width=20)

        # Button widgets
        encrypt_button = tk.Button(button_frame, text="Chiffrer")
        decrypt_button = tk.Button(button_frame, text="Déchiffrer")
        calculate_button = tk.Button(button_frame, text="Calculer")

        # Output display
        result_label = tk.Label(classique_window, text="Résultat:")
        result_label.pack(pady=5)
        result_text = tk.Text(classique_window, height=4, width=40)
        result_text.pack(pady=5)

        def execute_cipher(mode):
            cipher = cipher_var.get()
            text = text_entry.get().strip()
            param = param_entry.get().strip()
            param2 = param2_entry.get().strip() if cipher == "Affine" else ""

            # Input validation
            if not text:
                messagebox.showerror("Erreur", "Veuillez entrer un texte.")
                return
            if cipher not in ["IC", "Substitution aleatoire"]:
                if not param:
                    messagebox.showerror("Erreur", "Veuillez entrer le premier paramètre (clé/décalage).")
                    return
                if cipher == "Affine" and not param2:
                    messagebox.showerror("Erreur", "Veuillez entrer le deuxième paramètre (b).")
                    return
            if cipher == "OTP" and len(param) != len(text):
                messagebox.showerror("Erreur", "La clé OTP doit avoir la même longueur que le texte.")
                return
            if cipher == "César":
                try:
                    int(param)  # Ensure param is a number for César
                except ValueError:
                    messagebox.showerror("Erreur", "Le décalage pour César doit être un nombre entier.")
                    return
            if cipher == "Affine":
                try:
                    a = int(param)  # First param (a)
                    b = int(param2)  # Second param (b)
                    if math.gcd(a, 26) != 1:
                        messagebox.showerror("Erreur", "Le paramètre 'a' doit être premier avec 26 (par exemple, 1, 3, 5, 7, 11, 15, 17, 19, 21, 23, 25).")
                        return
                    if a <= 0 or b < 0:
                        messagebox.showerror("Erreur", "Le paramètre 'a' doit être positif et 'b' doit être non négatif.")
                        return
                except ValueError:
                    messagebox.showerror("Erreur", "Les paramètres pour Affine doivent être des nombres entiers.")
                    return

            try:
                result = ""
                if cipher == "César":
                    shift = int(param)
                    if mode == "encrypt":
                        result = Cesar.encrypt_cesar(shift, text)
                    else:
                        result = Cesar.decrypt_cesar(shift, text)
                elif cipher == "Vigenère":
                    if mode == "encrypt":
                        result = Vigenere.encrypt_vigenere(param, text)
                    else:
                        result = Vigenere.decrypt_vigenere(param, text)
                elif cipher == "OTP":
                    if mode == "encrypt":
                        result = otp.chiffrer_otp(text, param)
                    else:
                        result = otp.dechiffrer_otp(text, param)
                elif cipher == "Substitution aleatoire":
                    if mode == "encrypt":
                        key = substitution_aleatoire.generate_key()
                        result = substitution_aleatoire.encrypt(text, key)
                        result_text.delete(1.0, tk.END)
                        result_text.insert(tk.END, f"Clé: {key}\nRésultat: {result}")
                    else:
                        messagebox.showwarning("Avertissement", "Veuillez fournir la clé de chiffrement pour déchiffrer.")
                        return
                elif cipher == "Affine":
                    a = int(param)
                    b = int(param2)
                    if mode == "encrypt":
                        result = Affine.encrypt_affine(a, b, text)
                    else:
                        result = Affine.decrypt_affine(a, b, text)
                elif cipher == "Hill":
                    if mode == "encrypt":
                        result = Hill_cipher.encrypt_hill(text)
                    else:
                        result = Hill_cipher.decrypt_hill(text)
                elif cipher == "Playfair":
                    if mode == "encrypt":
                        result = playfair.chiffrer_playfair(param, text)
                    else:
                        result = playfair.dechiffrer_playfair(param, text)
                elif cipher == "IC":
                    result = IC.index_of_coincidence(text)

                if cipher != "Substitution aleatoire":  # Handled separately above
                    result_text.delete(1.0, tk.END)
                    result_text.insert(tk.END, result)
                # Clear entry fields for ciphers that use them
                if cipher not in ["IC", "Substitution aleatoire"]:
                    param_entry.delete(0, tk.END)
                    if cipher == "Affine":
                        param2_entry.delete(0, tk.END)
            except ValueError as e:
                messagebox.showerror("Erreur", f"Erreur dans les paramètres ou le texte : {str(e)}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Une erreur s'est produite : {str(e)}")

        def update_ui(*args):
            # Clear previous widgets
            for widget in param_frame.winfo_children():
                widget.pack_forget()
            for widget in button_frame.winfo_children():
                widget.pack_forget()

            cipher = cipher_var.get()
            if cipher in ["IC", "Substitution aleatoire"]:
                # Show only the calculate button for IC, encrypt/decrypt for Substitution
                if cipher == "IC":
                    calculate_button.config(command=lambda: execute_cipher("encrypt"))
                    calculate_button.pack(pady=5)
                else:
                    encrypt_button.config(command=lambda: execute_cipher("encrypt"))
                    decrypt_button.config(command=lambda: execute_cipher("decrypt"))
                    encrypt_button.pack(pady=5, side=tk.LEFT, padx=5)
                    decrypt_button.pack(pady=5, side=tk.LEFT, padx=5)
            else:
                # Show parameter fields
                param_label.pack(pady=5)
                param_entry.pack(pady=5)
                if cipher == "Affine":
                    param2_label.pack(pady=5)
                    param2_entry.pack(pady=5)
                # Show encrypt/decrypt buttons for other ciphers
                encrypt_button.config(command=lambda: execute_cipher("encrypt"))
                decrypt_button.config(command=lambda: execute_cipher("decrypt"))
                encrypt_button.pack(pady=5, side=tk.LEFT, padx=5)
                decrypt_button.pack(pady=5, side=tk.LEFT, padx=5)

        # Bind the UI update to cipher selection
        cipher_var.trace("w", update_ui)
        # Initial UI setup
        update_ui()




    def show_symetrique_menu(self):
        classique_window = tk.Toplevel(self.root)
        classique_window.title("Cryptographie Moderne symétrique")
        classique_window.geometry("700x600")
        classique_window.resizable(False, False)

        cipher_label = tk.Label(classique_window, text="Choisir un chiffrement:")
        cipher_label.pack(pady=5)

        cipher_var = tk.StringVar(classique_window)
        cipher_var.set("RC4")
        cipher_options = ["RC4", "DES", "AES"]
        cipher_menu = ttk.OptionMenu(classique_window, cipher_var, cipher_var.get(), *cipher_options)
        cipher_menu.pack(pady=5)

        text_label = tk.Label(classique_window, text="Entrer le texte:")
        text_label.pack(pady=5)
        text_entry = tk.Entry(classique_window, width=40)
        text_entry.pack(pady=5)

        param_frame = tk.Frame(classique_window)
        param_frame.pack(pady=5)
        button_frame = tk.Frame(classique_window)
        button_frame.pack(pady=5)

        param_label = tk.Label(param_frame, text="Clé:")
        param_entry = tk.Entry(param_frame, width=20)

        encrypt_button = tk.Button(button_frame, text="Chiffrer")
        decrypt_button = tk.Button(button_frame, text="Déchiffrer")

        result_label = tk.Label(classique_window, text="Résultat:")
        result_label.pack(pady=5)
        result_text = tk.Text(classique_window, height=4, width=40)
        result_text.pack(pady=5)

        def execute_cipher(mode):
            cipher = cipher_var.get()
            text = text_entry.get().strip()
            key = param_entry.get().strip()

            if not text:
                messagebox.showerror("Erreur", "Veuillez entrer un texte.")
                return
            if not key:
                messagebox.showerror("Erreur", "Veuillez entrer une clé.")
                return
            if cipher == "AES" and len(key) not in [16, 24, 32]:
                messagebox.showerror("Erreur", "La clé AES doit être de 16, 24 ou 32 caractères.")
                return
            if cipher == "DES" and len(key) != 8:
                messagebox.showerror("Erreur", "La clé DES doit être de 8 caractères.")
                return

            try:
                result = ""
                if cipher == "RC4":
                    if mode == "encrypt":
                        resultTemp = RC4.rc4(key, text)
                        result = resultTemp.hex()
                    else:
                        resultTemp = RC4.rc4(key, text)
                        result = resultTemp.decode()
                elif cipher == "DES":
                    if mode == "encrypt":
                        result = DES.des_encrypt(text, key)
                    else:
                        result = DES.des_encrypt(text, key)
                elif cipher == "AES":
                    if mode == "encrypt":
                        result = AES.encrypt(text, key).hex()
                    else:
                        ciphertext = bytes.fromhex(text.strip())
                        result = AES.decrypt(ciphertext, key).decode('utf-8', errors='ignore')

                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, result)
                param_entry.delete(0, tk.END)
            except ValueError as e:
                messagebox.showerror("Erreur", f"Erreur dans les paramètres ou le texte : {str(e)}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Une erreur s'est produite : {str(e)}")        
        def update_ui(*args):
            for widget in param_frame.winfo_children():
                widget.pack_forget()
            for widget in button_frame.winfo_children():
                widget.pack_forget()

            param_label.pack(pady=5)
            param_entry.pack(pady=5)
            encrypt_button.config(command=lambda: execute_cipher("encrypt"))
            decrypt_button.config(command=lambda: execute_cipher("decrypt"))
            encrypt_button.pack(pady=5, side=tk.LEFT, padx=5)
            decrypt_button.pack(pady=5, side=tk.LEFT, padx=5)

        cipher_var.trace("w", update_ui)
        update_ui()


    def show_asymetrique_menu(self):
        # Create a new window
        classique_window = tk.Toplevel(self.root)
        classique_window.title("Cryptographie Moderne asymétrique")
        classique_window.geometry("700x600")
        classique_window.resizable(False, False)  # Disable resizing

        # Dropdown menu for selecting cipher
        cipher_label = tk.Label(classique_window, text="Choisir un chiffrement:")
        cipher_label.pack(pady=5)

        cipher_var = tk.StringVar(classique_window)
        cipher_var.set("RSA")  # Default selection
        cipher_options = ["RSA", "ElGamal", "Chiffrement_homomorphe"]
        cipher_menu = ttk.OptionMenu(classique_window, cipher_var, cipher_var.get(), *cipher_options)
        cipher_menu.pack(pady=5)

        # Text entry field
        text_label = tk.Label(classique_window, text="Entrer le texte:")
        text_label.pack(pady=5)
        text_entry = tk.Entry(classique_window, width=40)
        text_entry.pack(pady=5)

        # Container for dynamic widgets
        param_frame = tk.Frame(classique_window)
        param_frame.pack(pady=5)
        button_frame = tk.Frame(classique_window)
        button_frame.pack(pady=5)

        

        # Button widgets
        encrypt_button = tk.Button(button_frame, text="Chiffrer")
        decrypt_button = tk.Button(button_frame, text="Déchiffrer")
       

        # Output display
        result_label = tk.Label(classique_window, text="Résultat:")
        result_label.pack(pady=5)
        result_text = tk.Text(classique_window, height=4, width=40)
        result_text.pack(pady=5)

        def execute_cipher(mode):
            cipher = cipher_var.get()
            text = text_entry.get().strip()
            

            # Input validation
            if not text:
                messagebox.showerror("Erreur", "Veuillez entrer un texte.")
                return
   
            
            try:
                result = ""
                if cipher == "RSA":
                    public_key, private_key = RSA.generate_rsa_keys(bits=1024)
                    if mode == "encrypt":
                        result = RSA.rsa_encrypt(text,public_key)
                    else:
                        result = RSA.rsa_decrypt(text,private_key)
                elif cipher == "ElGamal":
                    public_key, private_key = Elgamal.generate_elgamal_keys(bits=1024)
                    if mode == "encrypt":
                        result = Elgamal.elgamal_encrypt(text,public_key)
                    else:
                        result = Elgamal.elgamal_decrypt(text,private_key)
                elif cipher == "Chiffrement_homomorphe":
                    if mode == "encrypt":
                        p, q, g, x, h = Homomorphe_Elgamal.generate_parameters()
                        result = otp.chiffrer_otp(text, param)
                    else:
                        result = otp.dechiffrer_otp(text, param)              
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, result)
            
            except ValueError as e:
                messagebox.showerror("Erreur", f"Erreur dans les paramètres ou le texte : {str(e)}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Une erreur s'est produite : {str(e)}")

        def update_ui(*args):
            for widget in param_frame.winfo_children():
                widget.pack_forget()
            for widget in button_frame.winfo_children():
                widget.pack_forget()

            
            encrypt_button.config(command=lambda: execute_cipher("encrypt"))
            decrypt_button.config(command=lambda: execute_cipher("decrypt"))
            encrypt_button.pack(pady=5, side=tk.LEFT, padx=5)
            decrypt_button.pack(pady=5, side=tk.LEFT, padx=5)
         

        cipher_var.trace("w", update_ui)
        update_ui()
    














  

    def show_protocol_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Choisir un protocole:").pack(pady=5)
        protocols = ["Identification_Feige_Fiat_Shamir", "Identification_Schnorr", "Diffie_Hellman", "Shamir"]
        self.var = tk.StringVar(value=protocols[0])
        tk.OptionMenu(self.root, self.var, *protocols).pack(pady=5)
        tk.Entry(self.root, textvariable=tk.StringVar(), width=50).pack(pady=5)
        tk.Button(self.root, text="Exécuter", command=self.run_protocol).pack(pady=5)



    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def encrypt_text(self):
        algo = self.var.get()
        text = self.root.winfo_children()[-2].get()
        try:
            module = importlib.import_module(algo)
            result = module.encrypt(text)
            messagebox.showinfo("Résultat", f"Texte chiffré: {result}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement: {str(e)}")

    def decrypt_text(self):
        algo = self.var.get()
        text = self.root.winfo_children()[-2].get()
        try:
            module = importlib.import_module(algo)
            result = module.decrypt(text)
            messagebox.showinfo("Résultat", f"Texte déchiffré: {result}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du déchiffrement: {str(e)}")

    def run_protocol(self):
        algo = self.var.get()
        text = self.root.winfo_children()[-2].get()
        try:
            module = importlib.import_module(algo)
            if algo == "Identification_Schnorr":
                p, q, g, x, y = module.generate_parameters()
                result = module.schnorr_protocol(text)
            elif algo == "Identification_Feige_Fiat_Shamir":
                result = module.feige_fiat_shamir_protocol(text)
            else:
                result = module.run(text) if hasattr(module, 'run') else "Protocole non implémenté"
            messagebox.showinfo("Résultat", f"Résultat: {result}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'exécution du protocole: {str(e)}")








#DONT CHANGE
    def sign_text(self):
        algo = self.var.get()
        text = self.message_var.get()
        
        if not text:
            messagebox.showerror("Erreur", "Veuillez entrer un message à signer")
            return
        try:
            
            if algo == "Signature_Elgamal":
                                
                public_key, private_key = Signature_Elgamal.generate_elgamal_keys(bits=1024)
                signature = Signature_Elgamal.elgamal_sign(text, private_key, public_key)
                
                messagebox.showinfo("Résultat", f"Signature ElGamal: {signature}")
            elif algo == "Signature_RSA":
               
                public_key, private_key = Signature_RSA.generate_rsa_keys(bits=512)
                signature = Signature_RSA.rsa_sign(text, private_key)
                
                messagebox.showinfo("Résultat", f"Signature RSA: {signature}")
            elif algo == "Standard_DSA":
                
                p, q, g = Standard_DSA.generate_dsa_parameters()
                private_key, public_key= Standard_DSA.generate_dsa_key_pair(p,q,g)
           
                text_bytes = text.encode('utf-8')
                signature = Standard_DSA.sign_message(text_bytes, private_key, p, q, g)
                
                messagebox.showinfo("Résultat", f"Signature DSA: {signature}")
            else:
                messagebox.showerror("Erreur", "Algorithme de signature non implémenté")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la signature: {str(e)}")

    def show_signature_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Choisir un algorithme de ture:").pack(pady=5)
        signatures = ["Signature_Elgamal", "Signature_RSA", "Standard_DSA"]
        self.var = tk.StringVar(value=signatures[0])
        tk.OptionMenu(self.root, self.var, *signatures).pack(pady=5)
        tk.Label(self.root, text="Entrez le message à signer:").pack(pady=5)
        self.message_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.message_var, width=50).pack(pady=5)
        tk.Button(self.root, text="Signer", command=self.sign_text).pack(pady=5)
     



    def show_hash_menu(self):
        self.clear_window()
        tk.Label(self.root, text="Choisir une fonction de hachage:").pack(pady=5)
        hashes = ["md5", "sha1", "sha256"]
        self.var = tk.StringVar(value=hashes[0])
        tk.OptionMenu(self.root, self.var, *hashes).pack(pady=5)
        tk.Entry(self.root, textvariable=tk.StringVar(), width=50).pack(pady=5)
        tk.Button(self.root, text="Hacher", command=self.hash_text).pack(pady=5)

    def hash_text(self):
        algo = self.var.get()
        text = self.root.winfo_children()[-2].get()
        hash_functions = {
            'md5': lambda x: importlib.import_module('Fonctions_Hachage').md5(x),
            'sha1': lambda x: importlib.import_module('Fonctions_Hachage').sha1(x),
            'sha256': lambda x: importlib.import_module('Fonctions_Hachage').sha256(x),
        }
        if algo in hash_functions:
            try:
                result = hash_functions[algo](text).hex()
                messagebox.showinfo("Résultat", f"Hachage: {result}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors du hachage: {str(e)}")
        else:
            messagebox.showerror("Erreur", "Fonction de hachage non implémentée")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()