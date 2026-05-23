import requests
import json
import hmac
import hashlib
from typing import Dict
# Предполагаем, что config.py лежит рядом
from config import *

class UrentAPI:
    BASE_URL = "https://app.urentbike.ru/gatewayclient/api"
    _SECRET_HEX = ""
    _XOR_KEY = 63
    
    def __init__(self):
        self.access_token = ACCESS_TOKEN
        self.refresh_token = REFRESH_TOKEN
        self.session = requests.Session()
        self._setup_base_headers()
    
    def _setup_base_headers(self):
        self.session.headers.update({
            "User-Agent": "Urent/1.96.0 (ru.urentbike.app; build:1960; Android 17) okhttp/5.1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "UR-Device-Id": DEVICE_ID,
            "UR-Version": "1.96.0",
            "UR-Platform": "Android",
            "UR-Session": SESSION_ID,
            "X-AppsFlyer-Id": APPSFLYER_ID,
            "UR-Country-Code": "rus",
            "UR-Brand": "URENT",
            "UR-Request-Version": "v2",
            "Authorization": f"Bearer {self.access_token}"
        })
    
    def _derive_hmac_key(self) -> bytes:
        raw = bytes.fromhex(self._SECRET_HEX)
        xored = bytes(b ^ self._XOR_KEY for b in raw)
        secret_str = xored.decode('utf-8')
        key = bytearray(64)
        secret_bytes = secret_str.encode('utf-8')
        copy_len = min(64, len(secret_bytes))
        key[:copy_len] = secret_bytes[:copy_len]
        return bytes(key)
    
    def _sign(self, body: bytes, query_params: Dict = None) -> str:
        key = bytearray(self._derive_hmac_key())
        client_bytes = CLIENT_ID.encode('utf-8')
        insert_pos = max(32, 64 - len(CLIENT_ID))
        copy_len = min(32, len(CLIENT_ID))
        key[insert_pos:insert_pos + copy_len] = client_bytes[:copy_len]
        
        ur_headers = {}
        for name, value in self.session.headers.items():
            if name.lower().startswith("ur-") and name.lower() != "ur-request-data":
                ur_headers[name.lower()] = value
        
        sorted_headers = sorted(ur_headers.items(), key=lambda x: x[0])
        header_values = "".join(v for _, v in sorted_headers)
        
        query_part = ""
        if query_params:
            sorted_params = sorted(query_params.items(), key=lambda x: x[0])
            for k, v in sorted_params:
                query_part += k + str(v)
        
        message = header_values + query_part
        if body:
            message += body.decode('utf-8')
        
        return hmac.new(bytes(key), message.encode('utf-8'), hashlib.sha256).hexdigest().upper()
    
    def _refresh_token_if_needed(self) -> bool:
        """Обновляет access_token, используя refresh_token"""
        try:
            print(" Токен истек. Попытка обновления...")
            url = f"{self.BASE_URL}/v1/connect/token"
            
            # Данные для x-www-form-urlencoded
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            }
            
            # Для подписи нам нужна сырая строка тела запроса
            # Важно: порядок полей в строке должен совпадать с тем, как их отправит requests
            body_str = f"grant_type=refresh_token&refresh_token={self.refresh_token}&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}"
            body_bytes = body_str.encode('utf-8')

            # Временно меняем Content-Type для корректной генерации подписи
            original_headers = self.session.headers.copy()
            self.session.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
            
            # Генерируем подпись для рефреш-запроса
            sig = self._sign(body_bytes, None)
            
            # Отправляем запрос
            resp = self.session.post(url, data=payload, headers={"UR-Request-Data": sig})
            
            # Возвращаем заголовки в исходное состояние
            self.session.headers["Content-Type"] = "application/json"
            
            if resp.status_code == 200:
                data = resp.json()
                self.access_token = data["access_token"]
                # Если сервер прислал новый refresh_token, сохраняем его
                if "refresh_token" in data:
                    self.refresh_token = data["refresh_token"]
                
                self.session.headers["Authorization"] = f"Bearer {self.access_token}"
                print("✅ Токен успешно обновлен!")
                return True
            else:
                print(f"❌ Не удалось обновить токен: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            print(f"❌ Ошибка при выполнении refresh_token: {e}")
            return False
    
    def _request(self, method: str, path: str, data: Dict = None, params: Dict = None, retry: bool = True) -> Dict:
        # Обновляем координаты в заголовках, если они переданы в параметрах
        if params:
            lat = params.get('latitude')
            lon = params.get('longitude')
            if lat and lon:
                self.session.headers["UR-Latitude"] = str(lat)
                self.session.headers["UR-Longitude"] = str(lon)
        
        url = f"{self.BASE_URL}{path}"
        
        # Подготовка тела для подписи
        if data:
            body_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
        else:
            body_bytes = b""
        
        # Подписываем запрос
        sig = self._sign(body_bytes, params)
        self.session.headers["UR-Request-Data"] = sig
        
        # Выполнение запроса
        resp = self.session.request(method, url, json=data, params=params)
        
        # Если получили 401, пробуем обновиться один раз
        if resp.status_code == 401 and retry:
            if self._refresh_token_if_needed():
                # Повторяем запрос с новым токеном (retry=False чтобы не уйти в бесконечный цикл)
                return self._request(method, path, data, params, retry=False)
        
        if resp.status_code != 200:
            print(f" Ошибка запроса {path}: HTTP {resp.status_code}")
            return {}
        
        return resp.json()

    def get_transports(self, lat: float, lon: float, radius: float = 3000.0) -> Dict:
        params = {
            "latitude": lat, 
            "longitude": lon, 
            "radiusByMeters": float(radius),
            "useBluetooth": "false", 
            "zoom": 17,
            "includeEmptyParkings": "true", 
            "withEBikes": "true"
        }
        print(self._request("GET", "/v6/transports", params=params))
        return self._request("GET", "/v6/transports", params=params)

if __name__ == "__main__":
    api = UrentAPI()
    result = api.get_transports(TYUMEN_LAT, TYUMEN_LON)
    if result:
        count = len(result.get("entries", {}).get("transports", []))
        print(f"Найдено самокатов: {count}")
