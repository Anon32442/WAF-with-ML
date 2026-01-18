from flask import Flask, request, Response
import requests
import os
from urllib.parse import unquote
from core.db import init_db, session, RequestLog, BlacklistRule
from core.signatures import check_signatures
from core.ml_engine import learn_request, is_known_pattern, neural_network_analyze
import config

app = Flask(__name__)
init_db()

TARGET_SERVER = os.environ.get("TARGET_SERVER", "http://victim:80")

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    method = request.method
    payload_data = request.get_data(as_text=True) or ""
    full_path = request.full_path if request.query_string else request.path
    client_ip = request.remote_addr
    
    current_mode = config.MODE
    print(f"[{current_mode.upper()}] Request: {method} {full_path}")

    # BLACKLIST
    if session.query(BlacklistRule).filter_by(rule_type='ip', value=client_ip).first():
        return Response("Forbidden by SOC Policy", status=403)

    # LEARNING MODE
    if current_mode == 'learning':
        learn_request(method, full_path)
        return forward_request(request, path)

    # PRODUCTION MODE
    if current_mode == 'production':
        
        decoded_path = unquote(full_path)
        decoded_payload = unquote(payload_data)

        sig_detected = False
        if (check_signatures(full_path) or check_signatures(payload_data) or 
            check_signatures(decoded_path) or check_signatures(decoded_payload)):
            print(" ! Signature match detected")
            sig_detected = True

        if is_known_pattern(method, full_path) and not sig_detected:
            return forward_request(request, path)
        
        
        full_context = decoded_payload + decoded_path
        should_block_main, conf_main = neural_network_analyze(full_context, signature_triggered=sig_detected)
        
        max_conf = conf_main
        should_block = should_block_main
        reason = "url_context"


        if not should_block:
            # Проверяет гет параметры
            for param_name, param_value in request.args.items():
                # %27 = '
                val_decoded = unquote(param_value)
                
                is_bad, conf = neural_network_analyze(val_decoded, signature_triggered=sig_detected)
                if is_bad:
                    should_block = True
                    max_conf = conf
                    reason = f"param_{param_name}"
                    print(f"   !!! MALICIOUS PARAM DETECTED: {param_name}")
                    break

        # Логика решения
        if should_block:
            log_request(client_ip, method, full_path, payload_data, f"blocked_ai_{reason}", max_conf)
            return Response(f"Malicious Request Blocked by AI ({reason})", status=403)
        
        else:
            status = "allowed"
            if sig_detected or not is_known_pattern(method, full_path):
                learn_request(method, full_path)
                status = "auto_learned"
            
            log_request(client_ip, method, full_path, payload_data, status, max_conf)
            return forward_request(request, path)

def log_request(ip, method, path, payload, status, conf):
    try:
        log = RequestLog(src_ip=ip, method=method, path=path, payload=payload, status=status, ml_confidence=f"{conf:.4f}")
        session.add(log)
        session.commit()
    except:
        session.rollback()

def forward_request(req, path):
    try:
        url = f"{TARGET_SERVER}/{path}"
        headers = {k: v for k, v in req.headers if k != 'Host'}
        
        resp = requests.request(
            method=req.method, 
            url=url, 
            headers=headers,
            data=req.get_data(), 
            cookies=req.cookies,
            params=req.args, 
            allow_redirects=False
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers_resp = [(n, v) for n, v in resp.raw.headers.items() if n.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, headers_resp)
    except Exception as e:
        return Response(f"Backend Error: {e}", 502)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)