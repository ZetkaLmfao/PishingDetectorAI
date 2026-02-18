import tkinter as tk
from tkinter import messagebox
import numpy as np
from sklearn.linear_model import Perceptron
import csv
import os
import re
from datetime import datetime
import tldextract
import unicodedata
KNOWN_BRANDS = [
    'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
    'netflix', 'ebay', 'instagram', 'twitter', 'whatsapp', 'linkedin',
    'bank', 'banco', 'caixa', 'santander', 'bbva', 'bradesco', 'itau',
    'wells', 'chase', 'citibank', 'hsbc', 'barclays', 'visa', 'mastercard',
    'americanexpress', 'discover', 'uber', 'airbnb', 'booking', 'expedia',
    'walmart', 'target', 'costco', 'alibaba', 'tencent', 'baidu', 'yahoo',
    'outlook', 'hotmail', 'gmail', 'icloud', 'dropbox', 'adobe', 'zoom',
    'salesforce', 'oracle', 'sap', 'ibm', 'intel', 'nvidia', 'amd',
    'dell', 'hp', 'sony', 'samsung', 'lg', 'panasonic', 'spotify',
    'twitch', 'reddit', 'pinterest', 'snapchat', 'tiktok', 'telegram'
]

SUSPICIOUS_WORDS_LIST = ["login", "verify", "account", "secure", "update"]

BLOCKED_TLDS = ['google', 'amazon', 'facebook', 'apple', 'microsoft', 'instagram', 
                 'twitter', 'paypal', 'netflix', 'ebay', 'whatsapp', 'linkedin',
                 'adobe', 'spotify', 'zoom', 'slack', 'github', 'gitlab', 'bitbucket',
                 'dropbox', 'icloud', 'outlook', 'gmail', 'yahoo', 'hotmail']

SHORTENER_DOMAINS = [
    'bit.ly', 'bitly.com', 'tinyurl.com', 'shorturl.at', 'ow.ly', 'tiny.cc',
    'goo.gl', 'is.gd', 'buff.ly', 'clck.ru', 'adf.ly', 'short.link',
    'rebrand.ly', 'link.zip', 'cut.me', 'tiny.one', 'url.kr', 'short.pic',
    'v.gd', 'lnk.co', 'surl.li', 'u.to', 'cutt.ly', 'ulvis.net', 'x.co',
    't.co', 'shortened.me', 'tly.me', 'short.st', 'short.am', 'tiny.pl',
    'linktr.ee', 'buff.link', 'zii.link', 'link.tl', 'shorte.st'
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.win', '.loan', '.ga', '.cf', '.click', '.xyz', '.download', '.review']



def extract_features(url: str):
    length = len(url)
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    has_ip = 1 if domain.replace(".", "").isdigit() else 0

    hyphen_count = url.count("-")
    suspicious_chars = url.count("@") + hyphen_count + url.count("%")

    https = 1 if url.startswith("https://") else 0
    num_subdomains = domain.count(".")
    suspicious_words = sum(1 for w in SUSPICIOUS_WORDS_LIST if w in url.lower())

    has_special_chars = 1 if any(0x0300 <= ord(c) <= 0x036F for c in url) else 0
    has_long_numbers = 1 if re.search(r'\d{6,}', url) else 0
    has_many_hyphens = 1 if hyphen_count >= 3 else 0
    suspicious_subdomains = 1 if num_subdomains >= 4 else 0

    is_shortened = 1 if any(shortener in domain.lower() for shortener in SHORTENER_DOMAINS) else 0

    brand_with_numbers = 0
    domain_lower = domain.lower()
    
    def remove_accents(text):
        replacements = {
            'ç': 'c', 'č': 'c', 'ć': 'c', 'ã': 'a', 'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'å': 'a',
            'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
            'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
            'ñ': 'n', 'ý': 'y', 'ÿ': 'y', 'ø': 'o', 'æ': 'ae', 'œ': 'oe'
        }
        result = text
        for char, replacement in replacements.items():
            result = result.replace(char, replacement)
        return result
    
    brand_with_special_chars = 0
    domain_normalized = remove_accents(domain_lower)
    domain_ascii_only = ''.join(c for c in domain_lower if ord(c) < 128)
    
    if domain_normalized != domain_ascii_only:
        for brand in KNOWN_BRANDS:
            if brand in domain_normalized and brand not in domain_ascii_only:
                brand_with_special_chars = 1
                break
    
    for brand in KNOWN_BRANDS:
        if re.search(rf'{brand}[-]\d+', domain_lower):
            brand_with_numbers = 1
            break

    suspicious_brand_subdomain = 0
    domain_parts = domain_lower.replace('www.', '').split('.')
    if len(domain_parts) >= 3:
        main_domain = domain_parts[-2]
        subdomains = domain_parts[:-2]
        for subdomain in subdomains:
            for brand in KNOWN_BRANDS:
                if brand == subdomain or subdomain.startswith(brand[:3]):
                    for other_brand in KNOWN_BRANDS:
                        if other_brand == main_domain or other_brand in main_domain:
                            if brand != other_brand:
                                suspicious_brand_subdomain = 1
                                break
                    if suspicious_brand_subdomain:
                        break
            if suspicious_brand_subdomain:
                break

    multiple_brands_in_domain = 0
    domain_parts_split = domain_lower.replace('www.', '').split('.')[0].split('-')
    if len(domain_parts_split) >= 2:
        brand_count = 0
        for part in domain_parts_split:
            for brand in KNOWN_BRANDS:
                if part == brand or part.startswith(brand[:3]) or brand.startswith(part[:3]):
                    brand_count += 1
                    break
        if brand_count >= 2:
            multiple_brands_in_domain = 1

    suspicious_www_variation = 0
    url_lower = url.lower()
    if re.search(r'://ww\d+\.', url_lower) or re.search(r'://www\d+\.', url_lower):
        suspicious_www_variation = 1

    has_homoglyphs = 0
    if re.search(r'g0[o0]', domain_lower) or re.search(r'p[4a]yp[4a]l', domain_lower):
        has_homoglyphs = 1
    elif re.search(r'\d+.*[l1]', domain_lower) and re.search(r'[a-z]{4,}', domain_lower):
        if re.search(r'[0o][0o]', domain_lower) or re.search(r'[1l][1l]', domain_lower):
            has_homoglyphs = 1
    
    if any(0x0300 <= ord(c) <= 0x036F for c in domain):
        has_homoglyphs = 1

    has_suspicious_tld = 1 if any(tld in domain_lower for tld in SUSPICIOUS_TLDS) else 0

    excessive_length = 1 if length > 40 else 0
    multiple_special_symbols = 1 if url.count("@") > 1 or url.count("%") > 1 else 0

    repeating_chars = 0
    if re.search(r'([a-z])\1{3,}', domain_lower):
        repeating_chars = 1

    has_punycode = 1 if 'xn--' in domain_lower else 0
    has_ip_encoding = 0
    if re.search(r'(%[0-9a-f]{2})+', url_lower) and re.search(r'\d{1,3}', url):
        has_ip_encoding = 1

    excessive_subdomains = 1 if num_subdomains >= 5 else 0

    length_x_suspicious_chars = length * suspicious_chars
    subdomains_x_special_chars = num_subdomains * has_special_chars
    has_ip_x_suspicious_tld = has_ip * has_suspicious_tld
    https_x_special_chars = https * has_special_chars
    suspicious_chars_x_hyphens = suspicious_chars * has_many_hyphens

    suspicious_ratio = suspicious_chars / max(length, 1)
    domain_length_ratio = num_subdomains / max(length, 1)
    special_char_density = (has_special_chars + has_homoglyphs + has_punycode) / max(length, 1)

    multiple_risks = (has_special_chars + repeating_chars + has_homoglyphs + has_punycode +
                     has_ip_encoding + has_suspicious_tld)
    brand_confusion_score = suspicious_brand_subdomain * (num_subdomains + 1)
    subdomain_risk = suspicious_subdomains * (num_subdomains - 2)

    protocol_security = https * 1 + is_shortened * (-1) + has_ip * (-1)
    character_trustworthiness = (1 - has_special_chars) * (1 - has_homoglyphs) * (1 - repeating_chars)
    domain_legitimacy = (1 - has_suspicious_tld) * (1 - excessive_length)

    has_numeric_in_domain = 1 if re.search(r'\d', domain_lower) else 0
    has_underscore = 1 if '_' in url else 0
    has_multiple_dots = 1 if url.count('.') > 4 else 0
    digit_count = len(re.findall(r'\d', url))
    vowel_count = len(re.findall(r'[aeiou]', domain_lower))

    digit_ratio = digit_count / max(len(domain), 1)
    vowel_ratio = vowel_count / max(len(domain), 1)

    suspicion_score = (has_special_chars + repeating_chars + has_homoglyphs + has_punycode +
                      has_ip_encoding + has_suspicious_tld + suspicious_brand_subdomain +
                      brand_with_numbers + is_shortened + has_long_numbers + multiple_brands_in_domain)

    path_part = url.replace("http://", "").replace("https://", "").split("/", 1)[1] if "/" in url.replace("http://", "").replace("https://", "") else ""
    suspicious_path = 1 if any(w in path_part.lower() for w in SUSPICIOUS_WORDS_LIST) else 0
    
    domain_ends_with_number = 1 if re.search(r'\d+\.(com|org|net|io|tk|click|xyz|ml|win)$', domain_lower) else 0
    
    brand_mismatch = 0
    domain_parts = domain_lower.replace('www.', '').split('.')
    if len(domain_parts) >= 2:
        for brand in KNOWN_BRANDS:
            if any(brand in part for part in domain_parts[:-1]):
                if brand not in domain_parts[-2]:
                    brand_mismatch = 1
                    break
    
    path_with_credentials = 1 if any(cred in path_part.lower() for cred in ["admin", "login", "panel", "dashboard", "account", "user"]) else 0
    
    domain_name = domain_parts[-2] if len(domain_parts) >= 2 else domain
    subdomain_total_length = len(domain_lower) - len(domain_name) - 4
    unusual_domain_structure = 1 if len(domain_name) > 10 or (num_subdomains > 3 and subdomain_total_length > 20) else 0
    
    dash_brand_trick = 0
    domain_name_part = domain_parts[-2] if len(domain_parts) >= 2 else ""
    if "-" in domain_name_part:
        for brand in KNOWN_BRANDS:
            if brand in domain_name_part and domain_name_part.count("-") >= 1:
                dash_brand_trick = 1
                break
    
    many_dots_pattern = 1 if num_subdomains >= 5 else 0
    
    fake_ip_pattern = 1 if re.search(r'(\d{1,3}[-\.]\d{1,3}[-\.]\d{1,3}[-\.]\d{1,3})', domain_lower) else 0
    
    query_part = url.split("?", 1)[1] if "?" in url else ""
    suspicious_query = 1 if any(q in query_part.lower() for q in ["password", "email", "token", "session", "auth", "login"]) else 0
    
    fragment_part = url.split("#", 1)[1] if "#" in url else ""
    suspicious_fragment = 1 if any(f in fragment_part.lower() for f in ["admin", "panel", "login", "secure"]) else 0

    tld_brand_mismatch = 0
    tld = domain_lower.split(".")[-1]
    if tld in ["tk", "ml", "win", "loan", "ga", "cf", "click", "download", "review", "xyz"]:
        for brand in KNOWN_BRANDS:
            if brand in domain_lower:
                tld_brand_mismatch = 1
                break
    
    has_port_number = 1 if ":" in domain else 0
    
    double_slash = 1 if url.count("//") > 1 else 0
    
    path_destination_risk = suspicious_path + path_with_credentials
    domain_deception_score = brand_mismatch + dash_brand_trick + tld_brand_mismatch + domain_ends_with_number
    unusual_structure_risk = unusual_domain_structure + many_dots_pattern + fake_ip_pattern
    query_fragment_risk = suspicious_query + suspicious_fragment

    return [
        length, has_ip, suspicious_chars, https, num_subdomains, suspicious_words,
        has_special_chars, has_long_numbers, has_many_hyphens, suspicious_subdomains,
        is_shortened, brand_with_numbers, suspicious_brand_subdomain, brand_with_special_chars,
        suspicious_www_variation, has_homoglyphs, has_suspicious_tld, multiple_brands_in_domain,
        excessive_length, multiple_special_symbols, repeating_chars, has_punycode, has_ip_encoding,
        length_x_suspicious_chars, subdomains_x_special_chars, has_ip_x_suspicious_tld,
        https_x_special_chars, suspicious_chars_x_hyphens,
        suspicious_ratio, domain_length_ratio, special_char_density,
        multiple_risks, brand_confusion_score, subdomain_risk,
        protocol_security, character_trustworthiness, domain_legitimacy,
        has_numeric_in_domain, has_underscore, has_multiple_dots, digit_count, vowel_count,
        digit_ratio, vowel_ratio, suspicion_score,
        suspicious_path, domain_ends_with_number, brand_mismatch, path_with_credentials,
        unusual_domain_structure, dash_brand_trick, many_dots_pattern, fake_ip_pattern,
        suspicious_query, suspicious_fragment, tld_brand_mismatch, has_port_number, double_slash,
        path_destination_risk, domain_deception_score, unusual_structure_risk, query_fragment_risk,
        excessive_subdomains
    ]

def load_dataset():
    X = []
    y = []

    with open('dataset.csv', 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            X.append([
                int(row['length']),
                int(row['has_ip']),
                int(row['suspicious_chars']),
                int(row['https']),
                int(row['num_subdomains']),
                int(row['suspicious_words']),
                int(row['has_special_chars']),
                int(row['has_long_numbers']),
                int(row['has_many_hyphens']),
                int(row['suspicious_subdomains']),
                int(row['is_shortened']),
                int(row['brand_with_numbers']),
                int(row['suspicious_brand_subdomain']),
                int(row['brand_with_special_chars']),
                int(row['suspicious_www_variation']),
                int(row['has_homoglyphs']),
                int(row['has_suspicious_tld']),
                int(row['multiple_brands_in_domain']),
                int(row['excessive_length']),
                int(row['multiple_special_symbols']),
                int(row['repeating_chars']),
                int(row['has_punycode']),
                int(row['has_ip_encoding']),
                float(row['length_x_suspicious_chars']),
                float(row['subdomains_x_special_chars']),
                float(row['has_ip_x_suspicious_tld']),
                float(row['https_x_special_chars']),
                float(row['suspicious_chars_x_hyphens']),
                float(row['suspicious_ratio']),
                float(row['domain_length_ratio']),
                float(row['special_char_density']),
                float(row['multiple_risks']),
                float(row['brand_confusion_score']),
                float(row['subdomain_risk']),
                float(row['protocol_security']),
                float(row['character_trustworthiness']),
                float(row['domain_legitimacy']),
                int(row['has_numeric_in_domain']),
                int(row['has_underscore']),
                int(row['has_multiple_dots']),
                int(row['digit_count']),
                int(row['vowel_count']),
                float(row['digit_ratio']),
                float(row['vowel_ratio']),
                float(row['suspicion_score']),
                int(row['suspicious_path']),
                int(row['domain_ends_with_number']),
                int(row['brand_mismatch']),
                int(row['path_with_credentials']),
                int(row['unusual_domain_structure']),
                int(row['dash_brand_trick']),
                int(row['many_dots_pattern']),
                int(row['fake_ip_pattern']),
                int(row['suspicious_query']),
                int(row['suspicious_fragment']),
                int(row['tld_brand_mismatch']),
                int(row['has_port_number']),
                int(row['double_slash']),
                float(row['path_destination_risk']),
                float(row['domain_deception_score']),
                float(row['unusual_structure_risk']),
                float(row['query_fragment_risk']),
                int(row['excessive_subdomains'])
            ])
            y.append(int(row['label']))

    return np.array(X), np.array(y)

X_train, y_train = load_dataset()

def save_to_csv(url, prediction):
    csv_file = "urls_analise.csv"
    
    file_exists = os.path.isfile(csv_file)
    
    try:
        with open(csv_file, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            
            if not file_exists:
                writer.writerow(['Data/Hora', 'URL', 'Classificação', 'Status'])
            
            timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            status = 'Suspeita' if prediction == 1 else 'Legítima'
            writer.writerow([timestamp, url, 'Phishing Suspeita' if prediction == 1 else 'URL Legítima', status])
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao guardar em CSV: {str(e)}")

model = Perceptron(max_iter=1000, tol=1e-3, random_state=42)
model.fit(X_train, y_train)

history = []

def analyze_url():
    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning("Aviso", "Insira uma URL válida!")
        return

    has_scheme = url.lower().startswith("http://") or url.lower().startswith("https://")
    extracted = tldextract.extract(url)
    
    if not (has_scheme and extracted.domain and extracted.suffix):
        messagebox.showwarning("Aviso", "A URL precisa ter http/https e ser um domínio válido (ex: https://www.google.com).")
        return
    
    if extracted.suffix.lower() in BLOCKED_TLDS:
        messagebox.showwarning("Aviso", f"O TLD .{extracted.suffix} não é permitido.")
        return

    features = np.array(extract_features(url))
    prediction = model.predict(features.reshape(1, -1))[0]

    history.append({
        "url": url,
        "prediction": prediction
    })
    
    save_to_csv(url, prediction)

    if prediction == 0:
        result_label.config(text="✅ URL Legítima", fg="green")
    else:
        result_label.config(text="⚠️ Phishing Suspeita", fg="red")


def open_dashboard():
    import matplotlib.pyplot as plt
    
    if not history:
        messagebox.showinfo("Dashboard", "Ainda não existem dados.")
        return

    phishing = sum(1 for h in history if h["prediction"] == 1)
    legit = sum(1 for h in history if h["prediction"] == 0)
    plt.figure(figsize=(12, 6), num="Dashboard de Análise de URLs - Deteção de Phishing")
    plt.style.use('seaborn-v0_8-darkgrid')

    plt.subplot(1, 2, 1)
    colors = ['#2ecc71', '#e74c3c']
    plt.pie([legit, phishing], labels=["Legítimas", "Phishing"], 
            autopct='%1.1f%%', colors=colors, startangle=90)
    plt.title("Distribuição: Legítimas vs Phishing", fontweight='bold')

    plt.subplot(1, 2, 2)
    x = ['Legítimas', 'Phishing']
    y = [legit, phishing]
    bars = plt.bar(x, y, color=['#2ecc71', '#e74c3c'], alpha=0.7, edgecolor='black')
    plt.title("Comparação de Classificações", fontweight='bold')
    plt.ylabel("Quantidade")
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    plt.show()

root = tk.Tk()
root.title("Deteção de Phishing em URLs")
root.geometry("520x260")

tk.Label(root, text="Cole a URL para análise:", font=("Arial", 11)).pack(pady=10)

url_entry = tk.Entry(root, width=70)
url_entry.pack(pady=5)

tk.Button(root, text="Analisar URL", command=analyze_url).pack(pady=8)
tk.Button(root, text="Abrir Dashboard", command=open_dashboard).pack(pady=5)

result_label = tk.Label(root, text="", font=("Arial", 14))
result_label.pack(pady=15)

root.mainloop()
