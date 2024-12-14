import socket

def get_local_ip():
    try:
        # Membuat koneksi socket dummy untuk mendeteksi IP lokal
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Gunakan DNS publik Google
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error detecting local IP: {e}")
        return "127.0.0.1"  # Fallback ke localhost jika gagal

if __name__ == "__main__":
    # Panggil fungsi dan cetak hasilnya
    local_ip = get_local_ip()
    print(f"Detected local IP address: {local_ip}")
