import tkinter as tk
from tkinter import messagebox
import numpy as np
from cesar_crypto_system import encrypt_cesar, decrypt_cesar
from Affine_cipher import encrypt_affine, decrypt_affine
from Hill_cipher import encrypt_hill, decrypt_hill, is_invertible
from substitution_aleatoire import generate_key, encrypt as encrypt_sub, decrypt as decrypt_sub

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Classical Cryptography Tool")
        self.root.geometry("600x500")
        
        # Store substitution cipher key
        self.substitution_key = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Algorithm Selection
        tk.Label(self.root, text="Select Algorithm:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.algo_var = tk.StringVar(value="Caesar")
        
        algorithms = [
            ("Caesar Cipher", "Caesar"),
            ("Affine Cipher", "Affine"),
            ("Hill Cipher", "Hill"),
            ("Random Substitution", "Substitution")
        ]
        
        for i, (text, value) in enumerate(algorithms):
            tk.Radiobutton(self.root, text=text, variable=self.algo_var, 
                          value=value, command=self.toggle_key_fields).grid(row=0, column=i+1, sticky="w")

        # Mode Selection
        tk.Label(self.root, text="Select Mode:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.mode_var = tk.StringVar(value="Encrypt")
        tk.Radiobutton(self.root, text="Encrypt", variable=self.mode_var, value="Encrypt").grid(row=1, column=1, sticky="w")
        tk.Radiobutton(self.root, text="Decrypt", variable=self.mode_var, value="Decrypt").grid(row=1, column=2, sticky="w")

        # Text Entry
        tk.Label(self.root, text="Enter Text:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.text_entry = tk.Text(self.root, height=4, width=50)
        self.text_entry.grid(row=2, column=1, columnspan=4, padx=10, pady=10)

        # Key Fields
        self.create_key_fields()
        
        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.grid(row=4, column=1, columnspan=4, padx=10, pady=10)
        tk.Button(button_frame, text="Process", command=self.process_text).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Clear All", command=self.clear_all).pack(side=tk.LEFT, padx=5)

        # Output
        tk.Label(self.root, text="Output:").grid(row=5, column=0, padx=10, pady=10, sticky="w")
        self.output_text = tk.Text(self.root, height=4, width=50, state="normal")
        self.output_text.grid(row=5, column=1, columnspan=4, padx=10, pady=10)
        
        self.toggle_key_fields()
        
    def create_key_fields(self):
        # Caesar Key
        self.caesar_frame = tk.Frame(self.root)
        tk.Label(self.caesar_frame, text="Caesar Key:").pack(side=tk.LEFT)
        self.caesar_key_entry = tk.Entry(self.caesar_frame, width=10)
        self.caesar_key_entry.pack(side=tk.LEFT)
        
        # Affine Key
        self.affine_frame = tk.Frame(self.root)
        tk.Label(self.affine_frame, text="Affine Keys (a, b):").pack(side=tk.LEFT)
        self.affine_a_entry = tk.Entry(self.affine_frame, width=5)
        self.affine_a_entry.pack(side=tk.LEFT)
        self.affine_b_entry = tk.Entry(self.affine_frame, width=5)
        self.affine_b_entry.pack(side=tk.LEFT)
        
        # Hill Key
        self.hill_frame = tk.Frame(self.root)
        tk.Label(self.hill_frame, text="Hill Key (e.g., '2 3; 1 4'):").pack(side=tk.LEFT)
        self.hill_key_entry = tk.Entry(self.hill_frame, width=20)
        self.hill_key_entry.pack(side=tk.LEFT)
        
        # Substitution Key Display
        self.sub_frame = tk.Frame(self.root)
        tk.Label(self.sub_frame, text="Substitution Key:").pack(side=tk.LEFT)
        self.sub_key_display = tk.Label(self.sub_frame, text="", width=30)
        self.sub_key_display.pack(side=tk.LEFT)
        
    def toggle_key_fields(self):
        # Hide all frames first
        for frame in [self.caesar_frame, self.affine_frame, 
                     self.hill_frame, self.sub_frame]:
            frame.grid_forget()
        
        # Show the appropriate frame
        algo = self.algo_var.get()
        if algo == "Caesar":
            self.caesar_frame.grid(row=3, column=1, columnspan=4, sticky="w", padx=10, pady=10)
        elif algo == "Affine":
            self.affine_frame.grid(row=3, column=1, columnspan=4, sticky="w", padx=10, pady=10)
        elif algo == "Hill":
            self.hill_frame.grid(row=3, column=1, columnspan=4, sticky="w", padx=10, pady=10)
        elif algo == "Substitution":
            self.sub_frame.grid(row=3, column=1, columnspan=4, sticky="w", padx=10, pady=10)
    
    def process_text(self):
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        text = self.text_entry.get("1.0", tk.END).strip()
        
        try:
            if algo == "Caesar":
                key = int(self.caesar_key_entry.get())
                result = encrypt_cesar(key, text) if mode == "Encrypt" else decrypt_cesar(key, text)
                
            elif algo == "Affine":
                a = int(self.affine_a_entry.get())
                b = int(self.affine_b_entry.get())
                result = encrypt_affine(a, b, text) if mode == "Encrypt" else decrypt_affine(a, b, text)
                
            elif algo == "Hill":
                key_str = self.hill_key_entry.get()
                key_matrix = np.array([list(map(int, row.split())) for row in key_str.split(';')])
                if not is_invertible(key_matrix):
                    messagebox.showerror("Error", "Hill key matrix is not invertible!")
                    return
                result = encrypt_hill(text, key_matrix) if mode == "Encrypt" else decrypt_hill(text, key_matrix)
                
            elif algo == "Substitution":
                if mode == "Encrypt":
                    self.substitution_key = generate_key()
                    result = encrypt_sub(text, self.substitution_key)
                    self.sub_key_display.config(text=str(self.substitution_key))
                else:
                    if not self.substitution_key:
                        messagebox.showerror("Error", "No substitution key found! Encrypt first to generate key.")
                        return
                    result = decrypt_sub(text, self.substitution_key)
            
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.output_text.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
    
    def clear_all(self):
        self.text_entry.delete("1.0", tk.END)
        self.caesar_key_entry.delete(0, tk.END)
        self.affine_a_entry.delete(0, tk.END)
        self.affine_b_entry.delete(0, tk.END)
        self.hill_key_entry.delete(0, tk.END)
        self.substitution_key = None
        self.sub_key_display.config(text="")
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()