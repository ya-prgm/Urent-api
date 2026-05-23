import requests
import json
import hmac
import hashlib
from typing import Dict, Optional, List
from config import *

class UrentAPI:
    BASE_URL = "https://app.urentbike.ru/gatewayclient/api"
    _SECRET_HEX = "4a7155&**************d746d756c736**********************9550c745d0b6a75560d*****a7b6b540e4e0******************e776b7556774f584d6700"
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
        try:
            url = f"{self.BASE_URL}/v1/connect/token"
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            }
            body_str = f"grant_type=refresh_token&refresh_token={self.refresh_token}&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}"
            body_bytes = body_str.encode('utf-8')

            old_ct = self.session.headers["Content-Type"]
            self.session.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
            sig = self._sign(body_bytes, None)
            
            resp = self.session.post(url, data=payload, headers={"UR-Request-Data": sig})
            self.session.headers["Content-Type"] = old_ct
            
            if resp.status_code == 200:
                data = resp.json()
                self.access_token = data["access_token"]
                if "refresh_token" in data:
                    self.refresh_token = data["refresh_token"]
                self.session.headers["Authorization"] = f"Bearer {self.access_token}"
                return True
            return False
        except:
            return False
    
    def _request(self, method: str, path: str, data: Dict = None, params: Dict = None, retry: bool = True) -> Dict:
        # Авто-обновление координат в заголовках из параметров
        if params:
            lat = params.get('latitude') or params.get('lat')
            lon = params.get('longitude') or params.get('lng')
            if lat and lon:
                self.session.headers["UR-Latitude"] = str(lat)
                self.session.headers["UR-Longitude"] = str(lon)
        
        url = f"{self.BASE_URL}{path}"
        body_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8') if data else b""
        
        sig = self._sign(body_bytes, params)
        self.session.headers["UR-Request-Data"] = sig
        
        resp = self.session.request(method, url, json=data, params=params)
        
        if resp.status_code == 401 and retry:
            if self._refresh_token_if_needed():
                return self._request(method, path, data, params, retry=False)
        
        if resp.status_code != 200:
            return {}
        return resp.json()

    # --- МЕТОДЫ API ---

    def get_city_by_coordinates(self, lat: float, lon: float):
        """Определить город и его доступность"""
        return self._request("GET", "/v1/cities/by_coordinates", params={"lat": lat, "lng": lon})

    def get_transports(self, lat: float, lon: float, radius: float = 500.0):
        """Список самокатов и парковок на карте"""
        params = {
            "latitude": lat, "longitude": lon, "radiusByMeters": float(radius),
            "useBluetooth": "false", "zoom": 17, "includeEmptyParkings": "true", "withEBikes": "true"
        }
        return self._request("GET", "/v6/transports", params=params)

    def get_transport_details(self, transport_id: str):
        """Тарифы и состояние конкретного самоката"""
        params = {"isQrCode": "false", "referral": "", "withEBikes": "true"}
        return self._request("GET", f"/v3/transports/{transport_id}", params=params)

    def get_profile(self):
        """Полные данные профиля и статистика"""
        return self._request("GET", "/v1/profile")

    def get_profile_aggregated(self):
        """Краткая сводка (подписка, рейтинг)"""
        return self._request("GET", "/v1/profile/aggregated")

    def get_cards(self):
        """Привязанные карты"""
        return self._request("GET", "/v1/cards/withPendings")

    def get_payment_settings(self):
        """Настройки платежных систем и лимиты"""
        return self._request("GET", "/v1/places/my")

    def get_my_subscriptions(self):
        """Активные подписки"""
        return self._request("GET", "/v2/subscriptions/my")

    def get_available_subscriptions(self):
        """Подписки, доступные для покупки"""
        return self._request("GET", "/v5/subscriptions/get_availables")

    def get_my_minute_passes(self, city_id: str):
        """Купленные пакеты минут"""
        return self._request("GET", "/v1/customerMinutePass/my", params={"cityId": city_id})

    def get_orders_history(self, page: int = 1, limit: int = 10):
        """История поездок"""
        params = {"cPage": page, "iOnPage": limit, "order": "StartDateTimeUtc:desc"}
        return self._request("GET", "/v1/orders/my", params=params)

    def get_powerbanks(self, lat: float, lon: float, radius: float = 500.0):
        """Станции пауэрбанков рядом"""
        params = {"latitude": lat, "longitude": lon, "modelId": "null", "radiusbymeters": float(radius)}
        return self._request("GET", "/powerbank/v1/stations", params=params)

if __name__ == "__main__":
    api = UrentAPI()
    
    print("1. Проверка профиля...")
    prof = api.get_profile_aggregated()
    if prof:
        print(f"Рейтинг: {prof.get('userRatingValue')}")
        print(f"Подписка: {prof.get('subscriptionName')}")

    print("\n2. Поиск самокатов в Тюмени...")
    res = api.get_transports(TYUMEN_LAT, TYUMEN_LON)
    if res:
        scooters = res.get("entries", {}).get("transports", [])
        print(f"Найдено: {len(scooters)} шт.")
        if scooters:
            print(f"Первый в списке: {scooters[0]['displayedIdentifier']} (Заряд: {scooters[0]['batteryPercent']}%)")
