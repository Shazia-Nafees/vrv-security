# vrv-security
A robust log analysis tool that processes web server logs to identify patterns, potential security threats, and usage statistics. The system generates both CSV and HTML reports for easy data visualization and analysis.

Key Features
IP Traffic Analysis: Tracks and summarizes request frequency per IP address
Endpoint Monitoring: Identifies the most frequently accessed endpoints
Security Analysis: Detects suspicious activity based on failed login attempts
Multiple Output Formats:
Interactive HTML reports with sortable tables
CSV exports for data processing
Terminal output for quick viewing
Technical Implementation
Built in Python using standard libraries and minimal dependencies
Implements efficient data processing using Counter collections
Uses regex pattern matching for accurate log parsing
Generates responsive HTML reports with modern CSS styling

How to Use
Input
The system processes web server logs in the standard Apache/Nginx format
Sample data is provided in sample.log for testing and demonstration
You can replace sample.log with your own log file following the same format
Processing
Place your log file in the project directory
Run the analysis script:
python log_analysis.py
The script (log_analysis.py) processes the log file and performs:
Request frequency analysis
Endpoint usage tracking
Security threat detection
Output Options
Browser View:

Open log_analysis_report.html in any web browser or you can use this command in terminal to start the browser: start log_analysis_report.html
CSV Export:

Check log_analysis_results.csv for raw data
Suitable for further data processing or spreadsheet analysis
Terminal Output:

Immediate results displayed in console
Quick overview of key metrics
