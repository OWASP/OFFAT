sensitive_data_regex_patterns = {
    # General Data 
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    # 'passwordOrToken': r'(^|\s|")(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&_])[A-Za-z\d@$!%*#?&_]{10,}($|\s|")', # Assuming the password contains at least 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and is at least 8 characters long.
    'date': r'\b\d{2}/\d{2}/\d{4}\b',
    'ip': r'(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
    'ccn': r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',
    'jwtToken':r'(^|\s|")[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2}($|\s|")',
    
    # BRAZIL
    'BrazilCPF':r'\b(\d{3}\.){2}\d{3}\-\d{2}\b',

    # INDIA
    'pan': r'\b[A-Z]{5}\d{4}[A-Z]{1}\b',  # Assuming the format: AAAAB1234C (5 uppercase letters, 4 digits, 1 uppercase letter)
    'aadhaarCard': r'\b\d{4}\s\d{4}\s\d{4}\b',  # Assuming the format XXXX XXXX XXXX (4 digits, space, 4 digits, space, 4 digits)
    'PhoneNumberIN': r'((\+*)((0[ -]*)*|((91 )*))((\d{12})+|(\d{10})+))|\d{5}([- ]*)\d{6}',

    # US
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'PhoneNumberUS':r'(^|\s|")(1\s?)?(\d{3}|\(\d{3}\))[\s\-]?\d{3}[\s\-]?\d{4}(?:$|\s|")',

    ## AWS
    'AWSAccessKey': r'\bAKIA[0-9A-Z]{16}\b',  # Assuming the format: AKIA followed by 16 uppercase alphanumeric characters
    'AWSSecretKey': r'\b[0-9a-zA-Z/+]{40}\b',  # Assuming the format: 40 alphanumeric characters, including + and /
    'AWSResourceURL':r'\b([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.amazonaws.com*)\b',
    'AWSArnId': r'\barn:aws:[A-Za-z0-9-_]*\:[A-Za-z0-9-_]*\:[A-Za-z0-9-_]*\:[A-Za-z0-9-/_]*\b',
}