import re
import tldextract
import joblib  
from urllib.parse import urlparse
from urllib.parse import urlparse, unquote
import pandas as pd


def extraction_section(url): 
    data = pd.DataFrame([{"url": url}])

    # attribute 0
    data['URL_Length'] = data['url'].apply(len)
    
    # attribute 1
    characters_to_count = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']

    def count_character_occurrences(url, character):
        return url.count(character)

    for character in characters_to_count:
        data[f'{character}'] = data['url'].apply(lambda url: count_character_occurrences(url, character))


    # attribute 2
    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:
            return 1
        else:
            return 0
        
    data['Abnormal_URL'] = data['url'].apply(abnormal_url)

    # attribute 3
    def has_https(url):
        return int("https" in url)
    data['Has_HTTPS'] = data['url'].apply(has_https)



    # attribute 4
    def count_digits(string):
        return sum(1 for char in string if char.isdigit())
    data['Digit_Count'] = data['url'].apply(count_digits)

    # attribute 5
    def count_letters(string):
        return sum(1 for char in string if char.isalpha())
    data['Letter_Count'] = data['url'].apply(count_letters)
    
    shortening_pattern = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' \
                        r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' \
                        r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|' \
                        r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|' \
                        r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|' \
                        r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|' \
                        r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|' \
                        r'tr\.im|link\.zip\.net'


    # attribute 6
    def has_shortening_service(url):
        return int(re.search(shortening_pattern, url, flags=re.I) is not None)

    data['Has_Shortening_Service'] = data['url'].apply(has_shortening_service)
   

    ip_pattern = (
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'
    )


    # attribute 7
    def has_ip_address(url):
        return int(re.search(ip_pattern, url, flags=re.I) is not None)

    data['Has_IP_Address'] = data['url'].apply(has_ip_address)
   
    # attribute 8
    def check_for_malicious_code(url):
        # Check for 'javascript:' in the URL
        if re.search(r'javascript:', url):
            return 1
        
        # Check for attempts to inject script or use 'on' attributes
        if re.search(r'<\s*script', url, re.IGNORECASE) or re.search(r'on\w*=', url, re.IGNORECASE):
            return 1
        
        return 0
    data['Has_javascript_Code'] = data['url'].apply(check_for_malicious_code)


    # attribute 9
    def check_text_encoding(url):
        # Parse the URL
        parsed_url = urlparse(url)

        # Extract the text part
        text_part = parsed_url.path

        # Check for encoding
        decoded_text = unquote(text_part)
        
        # Check if the decoded text matches the original text
        if decoded_text == text_part:
            return 0  # No encoding found
        else:
            return 1  # Encoding found
    data['Has_Text_Encoding'] = data['url'].apply(check_text_encoding)
   
    return data.drop(['url', '*'],axis=1)

