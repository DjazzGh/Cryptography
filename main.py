
import tkinter as tk
from tkinter import messagebox
from cesar_crypto_system import encrypt_cesar, decrypt_cesar
from Affine_cipher import encrypt_affine, decrypt_affine

def process_text():
    selected_algo = algo_var.get()
    mode = mode_var.get()
    text = text_entry.get("1.0", tk.END).strip()

    try:
        if selected_algo == "Caesar":
            key = int(caesar_key_entry.get())
            result = encrypt_cesar(key, text) if mode == "Encrypt" else decrypt_cesar(key, text)

        elif selected_algo == "Affine":
            a = int(affine_a_entry.get())
            b = int(affine_b_entry.get())
            result = encrypt_affine(a, b, text) if mode == "Encrypt" else decrypt_affine(a, b, text)

        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", result)
    
    except ValueError:
        messagebox.showerror("Error", "Invalid input! Please enter numeric keys.")

def toggle_key_fields():
    if algo_var.get() == "Caesar":
        caesar_key_frame.grid()
        affine_key_frame.grid_remove()
    else:
        caesar_key_frame.grid_remove()
        affine_key_frame.grid()

def clear_all():
    text_entry.delete("1.0", tk.END)
    caesar_key_entry.delete(0, tk.END)
    affine_a_entry.delete(0, tk.END)
    affine_b_entry.delete(0, tk.END)
    output_text.delete("1.0", tk.END)

# GUI Setup
root = tk.Tk()
root.title("Classical Cryptography Tool")
root.geometry("500x400")

# Algorithm Selection
tk.Label(root, text="Select Algorithm:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
algo_var = tk.StringVar(value="Caesar")
algo_var.trace("w", lambda *args: toggle_key_fields())
tk.Radiobutton(root, text="Caesar Cipher", variable=algo_var, value="Caesar").grid(row=0, column=1, sticky="w")
tk.Radiobutton(root, text="Affine Cipher", variable=algo_var, value="Affine").grid(row=0, column=2, sticky="w")

# Mode Selection
tk.Label(root, text="Select Mode:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
mode_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="Encrypt").grid(row=1, column=1, sticky="w")
tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="Decrypt").grid(row=1, column=2, sticky="w")

# Text Entry
tk.Label(root, text="Enter Text:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
text_entry = tk.Text(root, height=4, width=40)
text_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=10)

# Caesar Key Entry
caesar_key_frame = tk.Frame(root)
caesar_key_frame.grid(row=3, column=1, columnspan=2, padx=10, pady=10, sticky="w")
tk.Label(caesar_key_frame, text="Caesar Key:").pack(side=tk.LEFT)
caesar_key_entry = tk.Entry(caesar_key_frame, width=10)
caesar_key_entry.pack(side=tk.LEFT)

# Affine Key Entry
affine_key_frame = tk.Frame(root)
affine_key_frame.grid(row=3, column=1, columnspan=2, padx=10, pady=10, sticky="w")
tk.Label(affine_key_frame, text="Affine Keys: a, b").pack(side=tk.LEFT)
affine_a_entry = tk.Entry(affine_key_frame, width=5)
affine_a_entry.pack(side=tk.LEFT)
affine_b_entry = tk.Entry(affine_key_frame, width=5)
affine_b_entry.pack(side=tk.LEFT)

# Buttons
button_frame = tk.Frame(root)
button_frame.grid(row=4, column=1, columnspan=2, padx=10, pady=10)
tk.Button(button_frame, text="Encrypt/Decrypt", command=process_text).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Clear All", command=clear_all).pack(side=tk.LEFT, padx=5)

# Output
tk.Label(root, text="Output:").grid(row=5, column=0, padx=10, pady=10, sticky="w")
output_text = tk.Text(root, height=4, width=40)
output_text.grid(row=5, column=1, columnspan=2, padx=10, pady=10)

# Initialize key fields
toggle_key_fields()

root.mainloop()