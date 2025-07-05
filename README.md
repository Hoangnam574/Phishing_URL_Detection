cat > README.md <<EOF
# Phishing URL Detection

## Mục tiêu

- Phân tích và đánh giá độ nguy hiểm của URL theo thang điểm 10.
- Sử dụng các API như:
  - Google Safe Browsing
  - Google Web Risk
  - VirusTotal
  - IPinfo
- Huấn luyện mô hình ML (XGBoost) với dữ liệu >2.8 triệu URL.
- Giao diện kiểm tra trực quan bằng Flask.

---

## Hướng dẫn cài đặt

### 1. Clone & cài môi trường
\`\`\`bash
git clone https://github.com/Hoangnam574/Phishing_URL_Detection.git
cd Phishing_URL_Detection

# Cài Git LFS nếu chưa có
git lfs install
git lfs pull

# Cài thư viện Python
pip install -r requirements.txt
# Hoặc:
conda env create -f environment.yml
conda activate phishing_env
\`\`\`

### 2. Chạy ứng dụng web
\`\`\`bash
cd web_app
python app.py
\`\`\`

---

## 📄 License
MIT © Hoangnam574
EOF
