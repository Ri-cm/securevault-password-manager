import base64
import json
import os
import tkinter as tk
from tkinter import ttk, messagebox

import csv
import time
from datetime import datetime
import psutil

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_NAME = "SecureVault Password Manager"
PRIVATE_KEY_AAD = b"securevault-private-key-v1"
ENTRY_AAD = b"securevault-entry-v1"
VAULT_KEY_BYTES = 32
NONCE_BYTES = 12

BENCHMARK_FILE = "benchmark_results.csv"

def save_benchmark(operation, duration, cpu, ram):
    file_exists = os.path.isfile(BENCHMARK_FILE)

    with open(BENCHMARK_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Waktu",
                "Pengujian",
                "Durasi (ms)",
                "CPU (%)",
                "RAM (MB)"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            operation,
            round(duration, 4),
            round(cpu, 2),
            round(ram, 2)
        ])


def db_connection():
    """Membuat koneksi PostgreSQL dari konfigurasi .env."""
    return psycopg.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "password_manager"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
        row_factory=dict_row,
    )


def initialize_database():
    """Membuat tabel jika belum tersedia."""
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    kdf_salt BYTEA NOT NULL,
                    public_key BYTEA NOT NULL,
                    encrypted_private_key BYTEA NOT NULL,
                    private_key_nonce BYTEA NOT NULL,
                    encrypted_vault_key BYTEA NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    nonce BYTEA NOT NULL,
                    ciphertext BYTEA NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)


def derive_master_key(master_password: str, salt: bytes) -> bytes:
    """Mengubah Master Password menjadi kunci 32 byte menggunakan Argon2id."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64 MiB
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def create_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, private_pem, public_pem


def rsa_oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_private_key(private_pem: bytes, derived_key: bytes):
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(derived_key).encrypt(
        nonce, private_pem, PRIVATE_KEY_AAD
    )
    return nonce, ciphertext


def decrypt_private_key(ciphertext: bytes, nonce: bytes, derived_key: bytes):
    return AESGCM(derived_key).decrypt(
        nonce, ciphertext, PRIVATE_KEY_AAD
    )


def encrypt_credential(data: dict, vault_key: bytes):
    nonce = os.urandom(NONCE_BYTES)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(vault_key).encrypt(nonce, plaintext, ENTRY_AAD)
    return nonce, ciphertext


def decrypt_credential(nonce: bytes, ciphertext: bytes, vault_key: bytes):
    plaintext = AESGCM(vault_key).decrypt(nonce, ciphertext, ENTRY_AAD)
    return json.loads(plaintext.decode("utf-8"))


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("850x570")
        self.root.minsize(760, 500)

        self.user_id = None
        self.email = None
        self.vault_key = None
        self.credentials_cache = []

        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.show_auth_screen()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_auth_screen(self):
        self.clear_window()
        container = ttk.Frame(self.root, padding=35)
        container.pack(expand=True)

        ttk.Label(
            container, text="SECUREVAULT",
            font=("Segoe UI", 23, "bold")
        ).pack(pady=(0, 5))
        ttk.Label(
            container, text="Password Manager dengan Enkripsi Berlapis",
            font=("Segoe UI", 10)
        ).pack(pady=(0, 25))

        form = ttk.Frame(container)
        form.pack()

        ttk.Label(form, text="Email").grid(row=0, column=0, sticky="w", pady=7)
        self.email_entry = ttk.Entry(form, width=38)
        self.email_entry.grid(row=0, column=1, pady=7, padx=10)

        ttk.Label(form, text="Master Password").grid(
            row=1, column=0, sticky="w", pady=7
        )
        self.master_entry = ttk.Entry(form, width=38, show="*")
        self.master_entry.grid(row=1, column=1, pady=7, padx=10)

        buttons = ttk.Frame(container)
        buttons.pack(pady=20)
        ttk.Button(buttons, text="Login", command=self.login).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(buttons, text="Buat Akun", command=self.register).grid(
            row=0, column=1, padx=6
        )

        ttk.Label(
            container,
            text="Master Password minimal 12 karakter. Simpan baik-baik; "
                 "tidak ada fitur reset password pada versi ini.",
            wraplength=460,
            justify="center",
        ).pack(pady=10)

        self.master_entry.bind("<Return>", lambda _event: self.login())
        self.email_entry.focus_set()

    def register(self):
        email = self.email_entry.get().strip().lower()
        master_password = self.master_entry.get()

        if not email or "@" not in email:
            messagebox.showwarning("Validasi", "Masukkan alamat email yang valid.")
            return
        if len(master_password) < 12:
            messagebox.showwarning(
                "Validasi", "Master Password harus minimal 12 karakter."
            )
            return

        try:
            salt = os.urandom(16)
            derived_key = derive_master_key(master_password, salt)

            _private_key, private_pem, public_pem = create_rsa_keypair()
            vault_key = AESGCM.generate_key(bit_length=256)

            private_nonce, encrypted_private = encrypt_private_key(
                private_pem, derived_key
            )

            public_key = serialization.load_pem_public_key(public_pem)
            encrypted_vault_key = rsa_oaep_encrypt(public_key, vault_key)

            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO users
                        (email, kdf_salt, public_key, encrypted_private_key,
                         private_key_nonce, encrypted_vault_key)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            email, salt, public_pem, encrypted_private,
                            private_nonce, encrypted_vault_key
                        ),
                    )
                    user_id = cur.fetchone()["id"]

            messagebox.showinfo(
                "Registrasi berhasil",
                "Akun berhasil dibuat. Silakan login menggunakan Master Password."
            )
            self.master_entry.delete(0, tk.END)

        except psycopg.errors.UniqueViolation:
            messagebox.showerror("Registrasi gagal", "Email sudah terdaftar.")
        except Exception as exc:
            messagebox.showerror("Registrasi gagal", f"Terjadi kesalahan: {exc}")

    
    def login(self):
        process = psutil.Process(os.getpid())

        start = time.perf_counter()
        cpu_start = process.cpu_times()

        def finish_benchmark(status):
            duration = (time.perf_counter() - start) * 1000

            cpu_end = process.cpu_times()

            cpu_time = (
                (cpu_end.user - cpu_start.user)
                + (cpu_end.system - cpu_start.system)
            )

            cpu_percent = (
                cpu_time / (duration / 1000) * 100
                if duration > 0 else 0
            )

            ram = process.memory_info().rss / (1024 * 1024)

            save_benchmark(
                f"LOGIN_{status}",
                duration,
                cpu_percent,
                ram
            )

        email = self.email_entry.get().strip().lower()
        master_password = self.master_entry.get()

        if not email or not master_password:
            finish_benchmark("INVALID_INPUT")
            messagebox.showwarning(
                "Validasi",
                "Email dan Master Password wajib diisi."
            )
            return

        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, email, kdf_salt,
                               encrypted_private_key,
                               private_key_nonce,
                               encrypted_vault_key
                        FROM users
                        WHERE email = %s
                    """, (email,))

                    user = cur.fetchone()

            if not user:
                finish_benchmark("FAILED")
                messagebox.showerror(
                    "Login gagal",
                    "Akun tidak ditemukan."
                )
                return

            derived_key = derive_master_key(
                master_password,
                bytes(user["kdf_salt"])
            )

            private_pem = decrypt_private_key(
                bytes(user["encrypted_private_key"]),
                bytes(user["private_key_nonce"]),
                derived_key
            )

            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )

            vault_key = rsa_oaep_decrypt(
                private_key,
                bytes(user["encrypted_vault_key"])
            )

            self.user_id = user["id"]
            self.email = user["email"]
            self.vault_key = vault_key

            finish_benchmark("SUCCESS")

            self.master_entry.delete(0, tk.END)
            self.show_dashboard()

        except (InvalidTag, ValueError):
            finish_benchmark("FAILED")

            messagebox.showerror(
                "Login gagal",
                "Master Password salah atau data kunci mengalami kerusakan."
            )

        except Exception as exc:
            finish_benchmark("ERROR")

            messagebox.showerror(
                "Login gagal",
                f"Terjadi kesalahan: {exc}"
            )

        email = self.email_entry.get().strip().lower()
        master_password = self.master_entry.get()

        if not email or not master_password:
            messagebox.showwarning(
                "Validasi", "Email dan Master Password wajib diisi."
            )
            return

        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, email, kdf_salt, encrypted_private_key,
                               private_key_nonce, encrypted_vault_key
                        FROM users WHERE email = %s
                        """,
                        (email,),
                    )
                    user = cur.fetchone()

            if not user:
                messagebox.showerror("Login gagal", "Akun tidak ditemukan.")
                return

            derived_key = derive_master_key(master_password, bytes(user["kdf_salt"]))
            private_pem = decrypt_private_key(
                bytes(user["encrypted_private_key"]),
                bytes(user["private_key_nonce"]),
                derived_key,
            )
            private_key = serialization.load_pem_private_key(
                private_pem, password=None
            )
            vault_key = rsa_oaep_decrypt(
                private_key, bytes(user["encrypted_vault_key"])
            )

            self.user_id = user["id"]
            self.email = user["email"]
            self.vault_key = vault_key
            self.master_entry.delete(0, tk.END)
            self.show_dashboard()

        except (InvalidTag, ValueError):
            messagebox.showerror(
                "Login gagal",
                "Master Password salah atau data kunci mengalami kerusakan."
            )
        except (InvalidTag, ValueError):
            finish_benchmark("FAILED")

            messagebox.showerror(
                "Login gagal",
                "Master Password salah atau data kunci mengalami kerusakan."
            )

        except Exception as exc:
            finish_benchmark("ERROR")

            messagebox.showerror(
                "Login gagal",
                f"Terjadi kesalahan: {exc}"
            )

    def logout(self):
        self.user_id = None
        self.email = None
        self.vault_key = None
        self.credentials_cache = []
        self.show_auth_screen()

    def show_dashboard(self):
        self.clear_window()

        header = ttk.Frame(self.root, padding=(18, 15))
        header.pack(fill="x")
        ttk.Label(
            header, text="SecureVault",
            font=("Segoe UI", 19, "bold")
        ).pack(side="left")
        ttk.Label(header, text=self.email).pack(side="left", padx=18)
        ttk.Button(header, text="Logout", command=self.logout).pack(side="right")

        ttk.Separator(self.root).pack(fill="x")

        content = ttk.Frame(self.root, padding=18)
        content.pack(fill="both", expand=True)

        ttk.Label(
            content, text="Daftar Kredensial",
            font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=(0, 10))

        columns = ("website", "username", "updated")
        self.tree = ttk.Treeview(
            content, columns=columns, show="headings", height=15
        )
        self.tree.heading("website", text="Website / Aplikasi")
        self.tree.heading("username", text="Username / Email")
        self.tree.heading("updated", text="Terakhir Diperbarui")
        self.tree.column("website", width=250)
        self.tree.column("username", width=250)
        self.tree.column("updated", width=190)
        self.tree.pack(fill="both", expand=True)

        actions = ttk.Frame(content)
        actions.pack(fill="x", pady=14)
        ttk.Button(actions, text="Tambah", command=self.add_credential).pack(
            side="left", padx=(0, 7)
        )
        ttk.Button(actions, text="Lihat Detail", command=self.view_credential).pack(
            side="left", padx=7
        )
        ttk.Button(actions, text="Edit", command=self.edit_credential).pack(
            side="left", padx=7
        )
        ttk.Button(actions, text="Hapus", command=self.delete_credential).pack(
            side="left", padx=7
        )
        self.refresh_credentials()

    def refresh_credentials(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.credentials_cache = []
        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, nonce, ciphertext, updated_at
                        FROM credentials
                        WHERE user_id = %s
                        ORDER BY updated_at DESC
                        """,
                        (self.user_id,),
                    )
                    rows = cur.fetchall()
                    

            for row in rows:
                data = decrypt_credential(
                    bytes(row["nonce"]),
                    bytes(row["ciphertext"]),
                    self.vault_key,
                )
                item = {
                    "id": row["id"],
                    "data": data,
                    "updated_at": row["updated_at"],
                }
                self.credentials_cache.append(item)
                self.tree.insert(
                    "", "end", iid=str(row["id"]),
                    values=(
                        data.get("website", ""),
                        data.get("username", ""),
                        row["updated_at"].strftime("%Y-%m-%d %H:%M"),
                    )
                )
        except InvalidTag:
            messagebox.showerror(
                "Kesalahan integritas",
                "Data tidak dapat diverifikasi. Ciphertext mungkin telah diubah."
            )
        except Exception as exc:
            messagebox.showerror("Database", f"Gagal memuat kredensial: {exc}")

    def selected_credential(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Pilih data", "Pilih salah satu kredensial.")
            return None
        selected_id = int(selection[0])
        for item in self.credentials_cache:
            if item["id"] == selected_id:
                return item
        return None

    def credential_form(self, title, initial=None):
        initial = initial or {}
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("440x370")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill="both", expand=True)

        fields = {}
        field_specs = [
            ("website", "Website / Aplikasi"),
            ("username", "Username / Email"),
            ("password", "Password"),
            ("notes", "Catatan"),
        ]

        for index, (key, label) in enumerate(field_specs):
            ttk.Label(frame, text=label).grid(
                row=index, column=0, sticky="w", pady=9
            )
            if key == "notes":
                widget = tk.Text(frame, width=30, height=4)
                widget.grid(row=index, column=1, sticky="ew", pady=7)
                widget.insert("1.0", initial.get(key, ""))
            else:
                widget = ttk.Entry(
                    frame, width=32,
                    show="*" if key == "password" else ""
                )
                widget.grid(row=index, column=1, sticky="ew", pady=7)
                widget.insert(0, initial.get(key, ""))
            fields[key] = widget

        result = {"data": None}

        def save():
            data = {}
            for key, widget in fields.items():
                if key == "notes":
                    data[key] = widget.get("1.0", "end-1c").strip()
                else:
                    data[key] = widget.get().strip()

            if not data["website"] or not data["username"] or not data["password"]:
                messagebox.showwarning(
                    "Validasi", "Website, username, dan password wajib diisi.",
                    parent=dialog
                )
                return

            result["data"] = data
            dialog.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=0, columnspan=2, pady=18)
        ttk.Button(buttons, text="Simpan", command=save).pack(
            side="left", padx=5
        )
        ttk.Button(buttons, text="Batal", command=dialog.destroy).pack(
            side="left", padx=5
        )

        frame.columnconfigure(1, weight=1)
        dialog.wait_window()
        return result["data"]

    def add_credential(self):
        data = self.credential_form("Tambah Kredensial")
        if not data:
            return

        try:
            nonce, ciphertext = encrypt_credential(data, self.vault_key)
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO credentials (user_id, nonce, ciphertext)
                        VALUES (%s, %s, %s)
                        """,
                        (self.user_id, nonce, ciphertext),
                    )
            self.refresh_credentials()
            messagebox.showinfo("Berhasil", "Kredensial berhasil disimpan.")
        except Exception as exc:
            messagebox.showerror("Gagal", f"Kredensial gagal disimpan: {exc}")

    def edit_credential(self):
        item = self.selected_credential()
        if not item:
            return

        data = self.credential_form("Edit Kredensial", item["data"])
        if not data:
            return

        try:
            nonce, ciphertext = encrypt_credential(data, self.vault_key)
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE credentials
                        SET nonce = %s, ciphertext = %s,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s AND user_id = %s
                        """,
                        (nonce, ciphertext, item["id"], self.user_id),
                    )
            self.refresh_credentials()
            messagebox.showinfo("Berhasil", "Kredensial berhasil diperbarui.")
        except Exception as exc:
            messagebox.showerror("Gagal", f"Gagal memperbarui data: {exc}")

    def view_credential(self):
        item = self.selected_credential()
        if not item:
            return

        data = item["data"]
        dialog = tk.Toplevel(self.root)
        dialog.title("Detail Kredensial")
        dialog.geometry("430x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill="both", expand=True)

        for label, key in [
            ("Website / Aplikasi", "website"),
            ("Username / Email", "username"),
            ("Password", "password"),
            ("Catatan", "notes"),
        ]:
            ttk.Label(frame, text=label, font=("Segoe UI", 9, "bold")).pack(
                anchor="w", pady=(7, 1)
            )
            value_frame = ttk.Frame(frame)
            value_frame.pack(fill="x")
            value = ttk.Entry(value_frame)
            value.pack(side="left", fill="x", expand=True)
            value.insert(0, data.get(key, ""))
            value.configure(state="readonly")
            if key == "password":
                value.configure(show="*")
                def toggle(entry=value):
                    current = entry.cget("show")
                    entry.configure(show="" if current else "*")
                ttk.Button(
                    value_frame, text="Tampilkan", command=toggle
                ).pack(side="right", padx=5)

        ttk.Button(frame, text="Tutup", command=dialog.destroy).pack(pady=15)

    def delete_credential(self):
        item = self.selected_credential()
        if not item:
            return

        confirmed = messagebox.askyesno(
            "Konfirmasi",
            f"Hapus kredensial untuk {item['data'].get('website', '')}?"
        )
        if not confirmed:
            return

        try:
            with db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM credentials WHERE id = %s AND user_id = %s",
                        (item["id"], self.user_id),
                    )
            self.refresh_credentials()
            messagebox.showinfo("Berhasil", "Kredensial berhasil dihapus.")
        except Exception as exc:
            messagebox.showerror("Gagal", f"Gagal menghapus data: {exc}")


def main():
    load_dotenv()

    try:
        initialize_database()
    except Exception as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Koneksi Database Gagal",
            "Tidak dapat terhubung ke PostgreSQL.\n\n"
            f"Detail: {exc}\n\n"
            "Periksa service PostgreSQL dan konfigurasi file .env."
        )
        root.destroy()
        return

    root = tk.Tk()
    PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
