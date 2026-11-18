import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="Dashboard Audit Keamanan",
    layout="wide"
)

data = pd.read_csv("log_login.csv")

failed = data[data["Status"] == "Failed"]
success = data[data["Status"] == "Success"]
jumlah_ip = failed.groupby("IP Address").size()
ip_mencurigakan = jumlah_ip[jumlah_ip >= 3]

st.title("Dashboard Audit Keamanan Sistem Informasi")
st.caption("Studi Kasus 1 | Analisis Log Serangan Menggunakan Python dan COBIT 2019")

st.header("Ringkasan Aktivitas Login")

# Ringkasan menggunakan HTML sederhana
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(
        f"<h3>Total Login</h3><h1>{len(data)}</h1>",
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        f"<h3>Login Gagal</h3><h1>{len(failed)}</h1>",
        unsafe_allow_html=True
    )

with col3:
    st.markdown(
        f"<h3>Login Berhasil</h3><h1>{len(success)}</h1>",
        unsafe_allow_html=True
    )

st.divider()

st.header("Aktivitas Login Berdasarkan Status")

fig, ax = plt.subplots()
ax.bar(
    ["Login Gagal", "Login Berhasil"],
    [len(failed), len(success)]
)
ax.set_ylabel("Jumlah Aktivitas")
ax.set_title("Jumlah Aktivitas Login Berdasarkan Status")
st.pyplot(fig)
plt.close(fig)

st.header("IP Address yang Perlu Diperiksa")

st.table(
    ip_mencurigakan.rename("Jumlah Login Gagal").reset_index()
)

st.header("Kegagalan Login Berdasarkan IP")

fig, ax = plt.subplots()
jumlah_ip.sort_values().plot(kind="barh", ax=ax)
ax.set_xlabel("Jumlah Login Gagal")
ax.set_ylabel("IP Address")
st.pyplot(fig)
plt.close(fig)

st.header("Mapping Hasil Audit ke COBIT 2019")

mapping = pd.DataFrame({
    "Aspek Audit": [
        "Pemantauan aktivitas keamanan",
        "Pengawasan alamat IP",
        "Pengendalian akses pengguna",
        "Pencatatan aktivitas proses"
    ],
    "Tujuan Manajemen": [
        "DSS05", "DSS05", "DSS05", "DSS06"
    ]
})

st.table(mapping)

st.header("Temuan Audit")
st.write(f"- Terdapat {len(failed)} aktivitas login gagal.")
st.write("- IP 192.168.1.10 melakukan 4 kali login gagal.")
st.write("- IP 10.0.0.8 melakukan 3 kali login gagal.")
st.write(f"- Terdapat {len(success)} aktivitas login berhasil.")

st.header("Rekomendasi Perbaikan")
st.write("1. Membatasi jumlah percobaan login.")
st.write("2. Memantau alamat IP dengan login gagal berulang.")
st.write("3. Menerapkan autentikasi multifaktor (MFA).")
st.write("4. Memeriksa riwayat akses akun admin.")

st.caption("Sumber: Data simulasi yang diolah penulis (2026).")
