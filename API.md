# 🛴 Urent Private API Documentation (v1.96.0)
**Telegram - @ya_prgm**


**Telegram - @ya_prgm**

**Telegram - @ya_prgm**

**Telegram - @ya_prgm**

**Telegram - @ya_prgm**

**Telegram - @ya_prgm**

**Telegram - @ya_prgm**

**Telegram - @ya_prgm**

**Telegram - @ya_prgm**




Данный документ описывает протокол взаимодействия мобильного приложения Urent с сервером. API построено на базе REST и использует кастомный механизм подписи каждого запроса для защиты от модификации данных.

---

## 1. Общие сведения

| Параметр | Значение |
|:---|:---|
| **Base URL** | `https://app.urentbike.ru/gatewayclient/api` |
| **Content-Type** | `application/json` (для большинства запросов) или `application/x-www-form-urlencoded` (для авторизации) |
| **Авторизация** | `Authorization: Bearer <JWT>` |
| **Версия приложения** | 1.96.0 (build 1960) |
| **User-Agent** | `Urent/1.96.0 (ru.urentbike.app; build:1960; Android 17) okhttp/5.1.0` |

### Серверная инфраструктура

| Сервис | URL | Назначение |
|:---|:---|:---|
| **Gateway API** | `app.urentbike.ru` | Основной API-шлюз |
| **Identity Server** | `service.urentbike.ru/identity` | Issuer JWT-токенов |
| **Логирование** | `lg.service.urentbike.ru` | Ktor-клиент, сбор логов |
| **Feature Flags** | `app.urentbike.ru/flagr/api/v1/evaluation/batch` | Flagr, фича-тогглы |
| **Push-уведомления** | `api.wavesend.ru` | PushWoosh |
| **Аналитика** | `api.a.mts.ru` | AppMetrica (MTS) |
| **Атрибуция** | `2vvq71.launches.appsflyersdk.com` | AppsFlyer |
| **MTS ID (OAuth)** | `login.mts.ru` | Авторизация через МТС |

---

## 2. Безопасность и подпись запроса

Каждый запрос к API (кроме обновления токена) должен сопровождаться заголовком `UR-Request-Data`. Это HMAC-SHA256 подпись.

### 2.1 Алгоритм генерации подписи

**Источник в APK:** `ru.urentbike.core_network.impl.utils.HashUtil` (класс `Wp/c.java`)

#### Шаг 1: Подготовка ключа (Key Derivation)
1. Взять статический секрет (Hex):
   `4a71555967454c560d5d746d756c736********************d7106667e66735e0945d0b6a75560d0e77***************b6b540e4e096f075b6d725766667e776b7556774f584d6700`
2. Каждый байт XOR с числом **63** (0x3F) — поле `strreg` в `HashUtil.kt`.
3. Декодировать полученные байты в UTF-8 строку.
4. Создать массив из 64 байт (заполнен нулями).
5. Скопировать UTF-8 строку в начало массива (но не более 64 байт).
6. Вставить `CLIENT_ID` (`mobile.client.android`) начиная с позиции:
   `insert_pos = max(32, 64 - len(CLIENT_ID))`
   Копируется `min(32, len(CLIENT_ID))` байт.
7. Итоговый массив — ключ HMAC.

#### Шаг 2: Формирование сообщения (Message)
*   **HEADERS**: все заголовки, начинающиеся на "UR-" (кроме `UR-Request-Data`) → ключи в нижний регистр → сортировка по алфавиту → склеить значения без разделителей.
*   **QUERY**: все query-параметры → сортировка по ключу → склеить `key + value`.
*   **BODY**: тело запроса как есть (JSON без пробелов).

`MESSAGE = HEADER_VALUES + QUERY_VALUES + BODY`

#### Шаг 3: Хеширование
`HMAC-SHA256(KEY, MESSAGE.encode('utf-8'))` → преобразовать в **hex** → перевести в **UPPERCASE**.

### 2.2 Реализация на Python

```python
import hmac
import hashlib

# Частично скрытый секрет для документации
_SECRET_HEX = "4a71555967454c560d5d746d756c736d7106667e66735e09550c745d0b6a7556****************************************************************6700"
_XOR_KEY = 63

def _derive_hmac_key(client_id: str) -> bytes:
    raw = bytes.fromhex(_SECRET_HEX)
    xored = bytes(b ^ _XOR_KEY for b in raw)
    secret_str = xored.decode('utf-8')
    key = bytearray(64)
    secret_bytes = secret_str.encode('utf-8')
    key[:min(64, len(secret_bytes))] = secret_bytes[:min(64, len(secret_bytes))]
    c_bytes = client_id.encode('utf-8')
    insert_pos = max(32, 64 - len(client_id))
    key[insert_pos:insert_pos + min(32, len(client_id))] = c_bytes[:min(32, len(client_id))]
    return bytes(key)

def _sign(body: bytes, query_params: dict, client_id: str, header_values: str) -> str:
    key = _derive_hmac_key(client_id)
    # Сбор query_values (сортировка ключей, склейка k+v)
    query_values = "".join(f"{k}{query_params[k]}" for k in sorted(query_params.keys())) if query_params else ""
    message = header_values + query_values + body.decode('utf-8')
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest().upper()
```

### 2.3 Ключевые классы в APK

| Класс | Файл | Назначение |
|:---|:---|:---|
| `Wp.c` | `HashUtil.kt` | Генерация подписи `UR-Request-Data` |
| `Vp.l` | `HashValidationInterceptor.kt` | Перехватчик Ktor, добавляет подпись к запросам |
| `Sp.t` | `HttpClient.kt` | Конфигурация HTTP-клиентов |
| `Tp.q` | `CoreNetworkModule.kt` | DI-модуль, создаёт `Wp.c` |
| `bo.C6668a` | `AppUtils.kt` | Создаёт `BuildConfig` с `clientId` и `clientSecret` |

---

## 3. Обязательные заголовки (Headers)

| Заголовок | Описание | Пример |
|:---|:---|:---|
| `Authorization` | JWT токен доступа | `Bearer eyJhbGci...****************` |
| `UR-Device-Id` | Уникальный ID устройства | `****************` |
| `UR-Version` | Версия приложения | `1.96.0` |
| `UR-Platform` | Платформа | `Android` |
| `UR-Session` | UUID сессии | `********-****-****-****-************` |
| `UR-Latitude` | Текущая широта | `57.1553383` |
| `UR-Longitude` | Текущая долгота | `65.5618633` |
| `UR-Request-Data` | HMAC подпись запроса | `A1B2C3D4...` |
| `UR-Country-Code` | Код страны | `rus` |
| `UR-Brand` | Бренд | `URENT` |
| `UR-Request-Version` | Версия подписи | `v2` |
| `UR-Client-Id` | ID клиента | `mobile.client.android` |
| `UR-User-Id` | ID пользователя | `************************` |
| `UR-Time-Zone` | Часовой пояс | `GMT+0` |
| `X-AppsFlyer-Id` | AppsFlyer ID | `*******************` |
| `Environment-Info` | Информация об устройстве | `plt:android,1.96.0(1960),mod:Google...,os:17,phone:79*********` |

---

## 4. Эндпоинты (Endpoints)

### 4.1 Авторизация (Identity Server: `service.urentbike.ru/identity`)

#### Получение/Обновление токена
`POST /v1/connect/token`  
**Content-Type:** `application/x-www-form-urlencoded`

**Параметры (password grant):**
| Параметр | Значение |
|:---|:---|
| `grant_type` | `password` |
| `username` | Номер телефона (`79*********`) |
| `password` | Код из СМС (`****`) |
| `client_id` | `mobile.client.android` |
| `client_secret` | `95YvCeLj74Zma3SPqyH8SwgzYMtMBj5C8FxPu5xHVExwJBjMn2t7S9L4HADQaAkc` |
| `scope` | `bike.api customers.api ... offline_access` |

**Параметры (refresh_token grant):**
| Параметр | Значение |
|:---|:---|
| `grant_type` | `refresh_token` |
| `refresh_token` | `************************` |
| `client_id` | `mobile.client.android` |
| `client_secret` | `95YvCeLj74Zma3SPqyH8SwgzYMtMBj5C8FxPu5xHVExwJBjMn2t7S9L4HADQaAkc` |

**Ответ (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...****************",
  "refresh_token": "************************",
  "expires_in": 1800,
  "token_type": "Bearer"
}
```

#### MTS ID (WebView OAuth)
`GET https://login.mts.ru/amserver/oauth2/authorize?...`  
После ввода пароля в WebView — редирект с `authorization_code` на `service.urentbike.ru`.

---

### 4.2 Карта и Транспорт

#### Поиск самокатов и парковок
`GET /v6/transports`

**Query-параметры:**
| Параметр | Тип | Описание |
|:---|:---|:---|
| `latitude` | float | Широта |
| `longitude` | float | Долгота |
| `radiusByMeters` | float | Радиус поиска (500, 2000, 3000, 5000) |
| `zoom` | int | Zoom карты (13-17) |
| `includeEmptyParkings` | bool | Включать пустые парковки |
| `withEBikes` | bool | Включать электровелосипеды |
| `useBluetooth` | bool | Поиск через Bluetooth |
| `status` | string | 🔥 **all** — показывает ночные самокаты! |

**Ответ (200 OK):**
```json
{
  "entries": {
    "transports": [
      {
        "batteryPercent": 94,
        "identifier": "S.******",
        "displayedIdentifier": "******",
        "type": "Scooter",
        "location": {
          "lat": 57.155,
          "long": 65.533
        }
      }
    ],
    "parkings": [
      {
        "id": "************************",
        "isEmpty": true,
        "countBikes": 0,
        "countScooters": 0,
        "location": {"lat": 57.155, "long": 65.532},
        "radius": 25
      }
    ]
  },
  "useZoneId": "************************",
  "succeeded": true
}
```

#### Детали самоката
`GET /v3/transports/{identifier}`  
Пример: `/v3/transports/S.104925?isQrCode=false&withEBikes=true`

**Ответ (200 OK):**
```json
{
  "identifier": "S.104925",
  "displayedIdentifier": "104-925",
  "type": "Scooter",
  "state": "Available",
  "charge": {
    "batteryPercent": 55.5,
    "remainKm": 17.5,
    "status": "Ok"
  },
  "rate": {
    "entries": [
      {
        "displayName": "Minute-by-Minute",
        "debit": {"valueFormatted": "6,99 ₽"},
        "periodMinute": 1
      }
    ]
  },
  "cityId": "************************",
  "modelName": "Ninebot Max Plus"
}
```

#### Определение города
`GET /v1/cities/by_coordinates?lat=57.155&lng=65.561`

**Ответ:**
```json
{
  "id": "************************",
  "name": "Tyumen",
  "availabilityStatus": "AVAILABLE",
  "succeeded": true
}
```

#### Станции пауэрбанков
`GET /powerbank/v1/stations?latitude=57.155&longitude=65.561&radiusbymeters=500.0`

**Ответ:**
```json
{"stations": [], "succeeded": true}
```

---

### 4.3 Профиль пользователя

#### Данные профиля
`GET /v1/profile`

**Ответ:**
```json
{
  "id": "************************",
  "phoneNumber": "79*********",
  "status": "New",
  "statistics": {
    "distance": 68866.86,
    "kcal": 1515.07,
    "elapsedSeconds": 34740.0,
    "tripCount": 11
  },
  "userRating": {
    "value": 100.0,
    "gradeTitle": "It's all good, there are no restrictions!",
    "gradeColor": "#21CA8B"
  }
}
```

#### Кошелёк и карты
*   `GET /v1/cards/withPendings`
*   `GET /v1/places/my`

**Ответ `places/my`:**
```json
{
  "currencySymbol": "₽",
  "culture": "ru-RU",
  "code": "RU",
  "alternativePaymentSystems": ["sbp", "sberbank", "mtsPay"],
  "cashbackSettings": {"isEnabled": true, "cashbackPercent": 5}
}
```

---

### 4.4 Подписки и пакеты минут
*   `GET /v2/subscriptions/my`
*   `GET /v5/subscriptions/get_availables`
*   `GET /v2/minutePass/availables?cityId={id}`
*   `GET /v1/customerMinutePass/my?cityId={id}`
*   `GET /v1/CustomerDailyPass/my`
*   `GET /v2/customerAbonements/my`

---

### 4.5 История поездок
`GET /v1/orders/my?cPage=1&iOnPage=10&order=StartDateTimeUtc:desc`

---

## 5. Обход ночной блокировки 

***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************
***************************************************************************************************

## 6. JWT-токен (структура)

**Расшифрованная payload-часть (пример):**
```json
{
  "nbf": 1779492735,
  "exp": 1779494535,
  "iss": "https://service.urentbike.ru/identity",
  "aud": ["bike.api", "customers.api", "location.api", "ordering.api", "payment.api"],
  "client_id": "mobile.client.android",
  "sub": "************************",
  "role": "CLIENT",
  "phone_number": "79*********",
  "phone": "79*********",
  "place.code": "RU",
  "place.country": "rus",
  "brand.code": "URENT",
  "jti": "********************************",
  "iat": 1779492735,
  "scope": ["bike.api", "customers.api", "offline_access"],
  "amr": ["custom"]
}
```
*Алгоритм подписи: RS256 (асимметричный — нельзя подделать)*

---

## 7. Feature Flags (Flagr)

`POST https://app.urentbike.ru/flagr/api/v1/evaluation/batch`  

**Примеры флагов:**
*   `auth_method`: `mtsid`
*   `offline_mode_config`: `Enabled`
*   `preferred_acquiring`: `MtsPay`
*   `min_app_version`: `1750`

---

## 8. Константы клиента

| Константа | Значение |
|:---|:---|
| `CLIENT_ID` | `mobile.client.android` |
| `CLIENT_SECRET` | `95YvCeLj74Zma3SPqyH8SwgzYMtMBj5C8FxPu5xHVExwJBjMn2t7S9L4HADQaAkc` |
| `APPLICATION_ID` | `ru.urentbike.app` |
| `VERSION_NAME` | `1.96.0` |
| `VERSION_CODE` | `1960` |
| `BRAND` | `URENT` |

---

## 9. Коды ответов

| Код | Описание |
|:---|:---|
| 200 | Успешно |
| 302 | Редирект (MTS ID) |
| 400 | Ошибка в параметрах или неверная подпись `UR-Request-Data` |
| 401 | Токен истек или неверен. Требуется `refresh_token` |
| 403 | Доступ запрещен (аккаунт заблокирован) |
| 404 | Эндпоинт не найден |

---

## 10. Инструменты реверс-инжиниринга

| Инструмент | Назначение |
|:---|:---|
| **JADX GUI** | Декомпиляция APK → Java/Kotlin код |
| **HTTP Toolkit** | Перехват HTTPS-трафика |
| **Frida** | Обход SSL Pinning на эмуляторе |
| **Android Studio Emulator** | Запуск APK без телефона |

---

## ⚠️ Disclaimer / Отказ от ответственности

### English
This repository and the information contained herein are strictly for educational, research, and informational purposes only. 
* **No Commercial Use:** This project is not intended for commercial use and is completely non-profit.
* **No Harm Intended:** The author does not encourage, support, or facilitate any illegal activities, service disruption, or unauthorized access to computer systems.
* **Intellectual Property:** All product names, logos, and brands are property of their respective owners. 
* **Terms of Service:** The user of this materials assumes all responsibility for compliance with the terms of service of the respective platforms. The author bears no responsibility for any misuse or damage caused by this repository.
* **Take-Down Notice:** If you are the copyright owner or a representative of the company and wish to have this content removed, please contact me directly, and I will delete this repository immediately.

### Русский
Данный репозиторий и содержащаяся в нем информация предоставлены исключительно в ознакомительных, учебных и научно-исследовательских целях.
* **Некоммерческое использование:** Проект не преследует коммерческих целей, является полностью некоммерческим и не используется для получения выгоды.
* **Отсутствие злого умысла:** Автор не призывает к совершению противоправных действий, не поощряет взлом, обход систем безопасности или нарушение работоспособности сторонних сервисов.
* **Интелlectualная собственность:** Все права на товарные знаки, названия сервисов и их логотипы принадлежат их законным владельцам.
* **Пользовательское соглашение:** Любое использование материалов данного репозитория производится пользователями на свой страх и риск. Автор не несет ответственности за возможные блокировки аккаунтов или иные последствия.
* **Правообладателям:** Если вы являетесь представителем компании или правообладателем и считаете, что данный репозиторий нарушает ваши права, пожалуйста, свяжитесь со мной. Материалы будут удалены незамедлительно по первому требованию.

