from .db import session, AllowedPattern
import hashlib
import re
import os
import joblib
import train_ai

model = None
MODEL_PATH = "/data/model.pkl"

def load_or_train_model():
    global model
    
    print(f"[ML] Checking model {MODEL_PATH}")

    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            print(f"[ML] successfully")
            return
        except Exception as e:
            print(f"[ML] Error loading: {e}. retrain!!!!!!!!!!!!")

    print("[ML] Model not found")
    
    try:
        train_ai.train()
        
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
            print(f"[ML] Training finished")
        else:
            print(f"[ML] error")
            
    except Exception as e:
        print(f"[ML] PLOHAYA OSHIBKA {e}")
        model = None

# Вайтлистики

def get_structure_hash(method, path):
    # 1. Заменяем цифры на {id}
    norm = re.sub(r'\d+', '{id}', path)
    # 2. Заменяем гет параметры на {val}
    norm = re.sub(r'=[^&]+', '={val}', norm)
    
    raw = f"{method}:{norm}"
    return hashlib.md5(raw.encode()).hexdigest()

def learn_request(method, path):
    # Вайтлист
    struct_hash = get_structure_hash(method, path)
    exists = session.query(AllowedPattern).filter_by(method_path_hash=struct_hash).first()
    
    if not exists:
        new_pattern = AllowedPattern(method_path_hash=struct_hash)
        session.add(new_pattern)
        session.commit()
        print(f"[LEARNING] Learned new pattern: {path}")

def is_known_pattern(method, path):
    # Провереят есть ли такой паттерн
    struct_hash = get_structure_hash(method, path)
    exists = session.query(AllowedPattern).filter_by(method_path_hash=struct_hash).first()
    return exists is not None

# Логика работы иишки

def neural_network_analyze(payload, signature_triggered=False):
    # signature_triggered = True, если регекс нашел что-то нашёл

    if model is None:
        print("Block")
        return True, 1.0

    try:
        probability = model.predict_proba([payload])[0][1]
        
        print(f"pupupu {probability:.4f}")

        threshold = 0.85

        
        if signature_triggered:
            if probability > 0.5:
                print(" -> Result: Block")
                return True, probability
            else:
                print(" -> Result: No Block")
                return False, probability
        
        should_block = probability > threshold
        return should_block, probability

    except Exception as e:
        print(f"AI Error: {e}")
        return True, 1.0



load_or_train_model()