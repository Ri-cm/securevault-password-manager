# SecureVault Password Manager

Aplikasi desktop Password Manager menggunakan Python Tkinter, PostgreSQL, AES-256-GCM, RSA-3072, RSA-OAEP SHA-256, dan Argon2id.

## 1. Persiapan

- Python 3.10 atau lebih baru
- PostgreSQL
- pgAdmin (opsional, untuk mengelola database)

## 2. Buat database

Buka pgAdmin atau Query Tool PostgreSQL, lalu jalankan:

```sql
CREATE DATABASE password_manager;
```

Tabel `users` dan `credentials` akan dibuat otomatis ketika aplikasi pertama kali dijalankan.

## 3. Siapkan project

Buka terminal pada folder project:

```bash
python -m venv .venv
```

Aktifkan virtual environment di Windows:

```bash
.venv\Scripts\activate
```

Install library:

```bash
pip install -r requirements.txt
```

## 4. Konfigurasi database

Salin `.env.example` menjadi `.env`, lalu isi password PostgreSQL milik sendiri:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=password_manager
DB_USER=postgres
DB_PASSWORD=password_postgresql_anda
```

Jangan membagikan file `.env` atau mengunggahnya ke GitHub.

## 5. Jalankan aplikasi

```bash
python main.py
```

Buat akun menggunakan email dan Master Password minimal 12 karakter. Setelah registrasi berhasil, login menggunakan akun tersebut.

## 6. Alur keamanan

1. Argon2id menurunkan kunci 32 byte dari Master Password dan salt acak.
2. Kunci hasil Argon2id melindungi RSA Private Key menggunakan AES-GCM.
3. AES-256-GCM mengenkripsi data kredensial dengan vault key acak.
4. RSA-OAEP dengan SHA-256 mengenkripsi vault key menggunakan RSA Public Key.
5. Database menyimpan ciphertext, nonce, encrypted vault key, dan encrypted private key.

## 7. Pengujian awal

- Daftarkan akun.
- Login dengan Master Password yang benar.
- Tambahkan satu kredensial uji, misalnya akun dummy.
- Tutup aplikasi dan buka kembali.
- Login dan pastikan kredensial dapat dibuka.
- Coba login dengan Master Password yang salah.
- Ubah ciphertext secara manual pada database di lingkungan pengujian dan pastikan verifikasi AES-GCM gagal.

## 8. Batasan versi awal

- Belum ada fitur reset Master Password. Jika Master Password hilang, data tidak dapat dipulihkan.
- Aplikasi ini merupakan prototipe akademik, belum diaudit untuk penggunaan produksi.
- Pengamanan terhadap malware, keylogger, memory dump, dan kompromi perangkat belum dicakup.
- Untuk penggunaan produksi, perlu ditambahkan rate limiting, auto-lock, penghapusan rahasia dari memori, backup terenkripsi, dan audit keamanan.

## 9. Catatan desain

Setiap data kredensial dienkripsi sebagai satu objek JSON. Karena website dan username juga berada dalam ciphertext, database tidak menyimpan metadata kredensial dalam bentuk terbuka. Nonce 96-bit dibuat acak untuk setiap operasi enkripsi AES-GCM dan tidak boleh digunakan ulang dengan vault key yang sama.
