
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="Dashboard Audit Keamanan",
    layout="wide"
)

data = pd.read_csv("log_login.csv")
data["Timestamp"] = pd.to_datetime(data["Timestamp"])

st.title("Dashboard Audit Keamanan Sistem Informasi")
st.caption("Studi Kasus 1 | Analisis Log Serangan Menggunakan Python dan COBIT 2019")

# FILTER DATA
st.header("Filter Aktivitas Login")

col1, col2 = st.columns(2)

with col1:
    pilihan_ip = st.multiselect(
        "Pilih IP Address",
        sorted(data["IP Address"].unique()),
        default=sorted(data["IP Address"].unique())
    )

with col2:
    pilihan_status = st.multiselect(
        "Pilih Status Login",
        sorted(data["Status"].unique()),
        default=sorted(data["Status"].unique())
    )

filtered = data[
    data["IP Address"].isin(pilihan_ip) &
    data["Status"].isin(pilihan_status)
]

# RINGKASAN
st.header("Ringkasan Aktivitas Login")

total = len(filtered)
gagal = len(filtered[filtered["Status"] == "Failed"])
berhasil = len(filtered[filtered["Status"] == "Success"])

c1, c2, c3 = st.columns(3)
c1.metric("Total Login", total)
c2.metric("Login Gagal", gagal)
c3.metric("Login Berhasil", berhasil)

st.divider()

# GRAFIK STATUS
st.header("Aktivitas Login Berdasarkan Status")

fig, ax = plt.subplots()
ax.bar(
    ["Login Gagal", "Login Berhasil"],
    [gagal, berhasil]
)
ax.set_ylabel("Jumlah Aktivitas")
ax.set_title("Jumlah Aktivitas Login Berdasarkan Status")
st.pyplot(fig)
plt.close(fig)

# DETAIL LOG
st.header("Detail Aktivitas Login")
st.dataframe(
    filtered.sort_values("Timestamp"),
    use_container_width=True
)

# ANALISIS IP
st.header("Analisis Kegagalan Login Berdasarkan IP")

jumlah_ip = (
    filtered[filtered["Status"] == "Failed"]
    .groupby("IP Address")
    .size()
)

fig, ax = plt.subplots()
if not jumlah_ip.empty:
    jumlah_ip.sort_values().plot(kind="barh", ax=ax)
    ax.set_xlabel("Jumlah Login Gagal")
    ax.set_ylabel("IP Address")
    st.pyplot(fig)
else:
    st.info("Tidak ada aktivitas login gagal pada filter ini.")
plt.close(fig)

# IP YANG PERLU DIPERIKSA
st.header("IP Address yang Perlu Diperiksa")

ip_mencurigakan = jumlah_ip[jumlah_ip >= 3]

if not ip_mencurigakan.empty:
    st.dataframe(
        ip_mencurigakan.rename(
            "Jumlah Login Gagal"
        ).reset_index(),
        use_container_width=True
    )
else:
    st.info("Tidak ditemukan IP dengan minimal 3 kali login gagal.")

# MAPPING COBIT
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

st.dataframe(mapping, use_container_width=True)

# TEMUAN
st.header("Temuan Audit")

st.write(f"- Terdapat {gagal} aktivitas login gagal pada data terfilter.")
st.write(f"- Terdapat {berhasil} aktivitas login berhasil pada data terfilter.")
st.write("- IP dengan minimal 3 kegagalan login perlu diperiksa lebih lanjut.")

# REKOMENDASI
st.header("Rekomendasi Perbaikan")

st.write("1. Membatasi jumlah percobaan login.")
st.write("2. Memantau alamat IP dengan kegagalan login berulang.")
st.write("3. Menerapkan autentikasi multifaktor (MFA).")
st.write("4. Memeriksa riwayat akses akun admin.")

# DOWNLOAD
st.header("Unduh Hasil Analisis")

csv = filtered.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Data Hasil Audit (CSV)",
    data=csv,
    file_name="hasil_audit_keamanan.csv",
    mime="text/csv"
)

st.caption("Sumber: Data simulasi yang diolah penulis (2026).")
