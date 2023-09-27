from re import findall
from .regexs import sensitive_data_regex_patterns


def detect_data_exposure(data:str)->dict:
    '''Detects data exposure against sensitive data regex 
    patterns and returns dict of matched results  
    
    Args:
        data (str): data to be analyzed for exposure

    Returns:
        dict: dictionary with tag as dict key and matched pattern as dict value
    '''
    # Dictionary to store detected data exposures
    detected_exposures = {}

    for pattern_name, pattern in sensitive_data_regex_patterns.items():
        matches = findall(pattern, data)
        if matches:
            detected_exposures[pattern_name] = matches

    return detected_exposures


if __name__ == '__main__':
    from json import dumps
    sample_test_data = dumps({
        "message" : "Please do not share your AWS Access Key: AKIAEXAMPLEKEY, AWS Secret Key: 9hsk24mv8wzJ3/78mx3p5x3E7N0P39n6Zq0RxTee, Aadhaar: 1234 5678 9012, PAN: ABCDE1234F, SSN: 123-45-6789, credit card: 1234-5678-9012-3456, or email: john.doe@example.com. You can reach me at +1 (555) 123-4567 or via email at contact@example.com. The event date is scheduled for 01/25/2023. The server IP is 192.168.1.1, and IPv6 is 2001:0db8:85a3:0000:0000:8a2e:0370:7334. Password examples: Passw0rd!, Strong@123, mySecret12#. My VISA Card: 4001778837951872"
    })

    # detect data exposure
    exposures = detect_data_exposure(sample_test_data)

    # Display the detected exposures
    for data_type, data_values in exposures.items():
        print(f"Detected {data_type}: {data_values}")