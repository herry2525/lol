#!/bin/bash

# Read the email addresses from email.txt
email_addresses=$(<email.txt)

# Collect scan results from /root/xmlrpc/xml
scan_results=$(</root/all1/2)

# Initialize the notfound.txt file
echo "" > notfound.txt

# Initialize the report number
report_number=1

# Loop through each scan result
while IFS= read -r scan_result; do
    # Extract vulnerability type, severity, and URL from the scan result
    if [[ $scan_result =~ \[([^]]+)\] ]]; then
        vulnerability_type="${BASH_REMATCH[1]}"
    else
        echo "Invalid scan result format: $scan_result"
        continue
    fi

    severity=$(echo "$scan_result" | awk '{print $3}')
    url=$(echo "$scan_result" | awk '{print $4}')
    url_field=$(echo "$scan_result" | awk '{print $5}')  # Extract the field using awk

    # Extract the domain name from the URL
    if [[ $url =~ ^https?://([^/]+) ]]; then
        domain="${BASH_REMATCH[1]}"
        # Remove subdomain from the domain
        domain_name=$(awk -F'.' '{print $(NF-1)"."$NF}' <<< "$domain")
    else
        echo "Invalid URL format: $url"
        continue
    fi

    # Check if the domain name matches any email domain
    matched_email=""
    for email_address in $email_addresses; do
        if [[ $email_address =~ @(.+)$ ]]; then
            email_domain="${BASH_REMATCH[1]}"
            if [[ $domain_name == $email_domain ]]; then
                matched_email="$email_address"
                break
            fi
        fi
    done

    if [[ -n $matched_email ]]; then
        # Set default description for the vulnerability report
        default_description="Title: Generic Token Usage
Severity: High

Generic tokens, also known as placeholder tokens, are placeholders used in programming or text-based applications to represent specific values or information. Instead of using actual data or variables, generic tokens serve as temporary substitutes that can be replaced with real values or variables at a later stage.

The impact of using generic tokens in various contexts can be significant. Here are a few potential impacts:

Flexibility and Reusability: Generic tokens provide flexibility by allowing placeholders that can be easily replaced with different values or variables as needed. This reusability simplifies development and maintenance efforts, as the same code or template can be used for different instances with varying data.

Security: Generic tokens can have an impact on security, particularly if used in sensitive contexts. Care must be taken to ensure that these tokens are properly protected and not exposed to unauthorized access or misuse. Any sensitive or personally identifiable information (PII) should not be used as generic tokens.

Reference:
OWASP Secure Coding Practices - OWASP provides a comprehensive guide to secure coding practices, including guidelines on the proper use of tokens and the potential security implications.
https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/"

        # Generate the vulnerability report
        report="Hello Team,

I have found a security issue in your system.

Vulnerability Type: $vulnerability_type
Severity: $severity
URL: $url
url_field: $url_field
Description:
$default_description

Best Regards,
Gaurang Maheta"

        # Set the subject line for the vulnerability report
        subject="Subject: Vulnerability Report - $vulnerability_type $report_number"

        # Send the vulnerability report via ssmtp
        echo -e "$subject\n$report" | ssmtp "$matched_email"

        echo "Report sent for $url"

        # Increment the report number
        ((report_number++))
    else
        echo "$url" >> notfound.txt
    fi
done <<< "$scan_results"

# Send the list of URLs with no email address via slackcat
slackcat -u https://hooks.slack.com/services/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 < notfound.txt

echo "Complete"
