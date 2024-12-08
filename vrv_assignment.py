import re

def analyze_log(log_file, failed_attempt_threshold= 10):
    # Initialize dictionaries to store counts
    # Initializing dictionaries to store counts
    ip_counts = {}
    endpoint_counts = {}
    failed_logins = {}

    # Process the log file line by line
    # Processing the log file line by line
    with open(log_file, 'r') as f:
        for line in f:
            # Extract IP address
            # Extracting IP address
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            if not ip_match:
                continue  # Skip lines without valid IP addresses
                continue  # Skiping lines without valid IP addresses
            ip_address = ip_match.group()

             # Extract endpoint
            # Extracting endpoint
            endpoint_match = re.search(r'\"(?:GET|POST) (.*?) HTTP', line)
            if not endpoint_match:
                continue  # Skip lines without valid endpoint information
                continue  # Skiping lines without valid endpoint information
            endpoint = endpoint_match.group(1)

            # Extract status code
            # Extracting status code
            status_code_match = re.search(r'HTTP/\d\.\d" (\d{3})', line)
            if not status_code_match:
                continue  # Skip lines without valid status code
                continue  # Skiping lines without valid status code
            status_code = int(status_code_match.group(1))

            # Count requests per IP address
            # Counting requests per IP address
            ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1

            # Count requests per endpoint
            # Counting requests per endpoint
            endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1

                        # Track failed login attempts (HTTP status 401)
            # Tracking failed login attempts (HTTP status 401)
            if status_code == 401:
                failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1

    # Sort results for display
    # Sorting results for display
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)
    sorted_failed_logins = sorted(
        [(ip, count) for ip, count in failed_logins.items() if count > failed_attempt_threshold],
        key=lambda x: x[1], reverse=True)

    # Print IP Address and Request Count
    # Printing IP Address and Request Count
    print("IP Address".ljust(20) + "Request Count")
    for ip, count in sorted_ip_counts:
        print(f"{ip.ljust(20)}{str(count).rjust(10)}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {endpoint_counts[most_accessed_endpoint]} times)")

      # Print Suspicious Activity Detected
    # Printing Suspicious Activity Detected
    print("\nSuspicious Activity Detected:")
    print("IP Address".ljust(20) + "Failed Login Attempts")
    for ip, count in sorted_failed_logins:
        if count > failed_attempt_threshold:
            print(f"{ip.ljust(20)}{str(count).rjust(10)}")

    # Write results to CSV file
    # Writing results to CSV file
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        # Section 1: Requests per IP Address
        # Section 1: Requesting per IP Address
        csv_writer.writerow(['IP Address', 'Request Count'])
        csv_writer.writerows(sorted_ip_counts)

        
        csv_writer.writerow(['IP Address', 'Failed Login Attempts'])
        csv_writer.writerows(sorted_failed_logins)

# Replace 'sample.log' with your actual log file path
# Replacing 'sample.log' with actual log file path
analyze_log(r"C:\VRV security\sample.log");

