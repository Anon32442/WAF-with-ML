import requests
import random
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODEL_PATH = "/data/model.pkl"

URLS = {
    'sqli': "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_SQLi.txt",
    'xss': "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payloads.txt",
}

MANUAL_ATTACKS = [
    "' OR 1=1",
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "admin' --",
    "admin' #",
    "' UNION SELECT",
    "1' ORDER BY 1",
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "1; DROP TABLE users",
    "' OR 'a'='a",
    "1' OR 1=1; //",
    "vlad' OR 1=1"
]

def download_payloads(url):
    print(f"Downloading from {url}...")
    try:
        r = requests.get(url)
        return [line.strip() for line in r.text.splitlines() if line.strip()]
    except Exception as e:
        print(f"Error {e}")
        return []

def get_good_queries():
    common_words = ["search", "user", "id", "login", "home", "product", "item", "page", "news", "contact", "about", "images", "css", "js"]
    good_data = []
    
    # Генерируем ОЧЕНЬ МНОГО хорошего трафика, чтобы модель понимала разницу
    for _ in range(5000):
        good_data.append(f"/{random.choice(common_words)}/{random.randint(1, 1000)}")
        good_data.append(f"/{random.choice(common_words)}?q={random.choice(common_words)}")
        good_data.append(f"search={random.choice(common_words)}")
        good_data.append(f"id={random.randint(1, 99999)}")
        good_data.append(f"Just normal text {random.randint(1, 100)}")
        good_data.append("It's a wonderful day")
        good_data.append("User profile page")
        good_data.append("Select an item")
    return good_data

def train():
    print("--- STARTING AI TRAINING ---")
    
    downloaded_bad = list(set(download_payloads(URLS['sqli']) + download_payloads(URLS['xss'])))
    
    boosted_attacks = MANUAL_ATTACKS * 50 
    
    bad_requests = downloaded_bad + boosted_attacks
    good_requests = get_good_queries()
    
    X = bad_requests + good_requests
    y = [1] * len(bad_requests) + [0] * len(good_requests)
    
    print(f"Dataset size: {len(X)} samples.")
    print(f" - Malicious: {len(bad_requests)}")
    print(f" - Benign: {len(good_requests)}")

    model = make_pipeline(
        TfidfVectorizer(min_df=1, analyzer='char', ngram_range=(1, 5)), 
        LogisticRegression(C=10.0)
    )

    model.fit(X, y)
    
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()