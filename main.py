import argparse
import logging
import re
import os
import sys
from faker import Faker
import chardet

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Anonymizes email headers by removing or replacing identifying information.')
    parser.add_argument('input_file', type=str, help='Path to the input email file.')
    parser.add_argument('output_file', type=str, help='Path to the output anonymized email file.')
    parser.add_argument('--keep-x-mailer', action='store_true', help='Keep the X-Mailer header (default: remove it).')
    parser.add_argument('--obfuscate-received', action='store_true', help='Obfuscate Received headers instead of removing them (default: remove).')
    parser.add_argument('--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the logging level.')
    return parser

def anonymize_email_headers(input_file, output_file, keep_x_mailer=False, obfuscate_received=False):
    """
    Anonymizes email headers by removing or replacing identifying information.

    Args:
        input_file (str): Path to the input email file.
        output_file (str): Path to the output anonymized email file.
        keep_x_mailer (bool): Whether to keep the X-Mailer header. Defaults to False (remove it).
        obfuscate_received (bool): Whether to obfuscate Received headers instead of removing them. Defaults to False (remove).
    """
    try:
        # Detect the encoding of the input file
        with open(input_file, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            encoding = result['encoding']
        
        if encoding is None:
            encoding = 'utf-8'  # Fallback to utf-8 if detection fails
        
        # Read the email file
        with open(input_file, 'r', encoding=encoding) as f:
            email_content = f.read()

        # Split the email into headers and body
        header_end_marker = '\n\n'
        if header_end_marker not in email_content:
            header_end_marker = '\r\n\r\n'
            if header_end_marker not in email_content:
                logging.error("Could not determine the header/body separator.")
                return

        header_part, body_part = email_content.split(header_end_marker, 1)
        headers = header_part.splitlines()

        anonymized_headers = []
        fake = Faker()

        for header in headers:
            if header.lower().startswith('received:'):
                if obfuscate_received:
                    # Obfuscate Received header
                    ip_address_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                    header = re.sub(ip_address_pattern, fake.ipv4(), header)
                    hostname_pattern = r'\[?([a-zA-Z0-9.-]+)\]?'  # match hostnames and hostnames enclosed in brackets
                    header = re.sub(hostname_pattern, fake.domain_name(), header)  # replace hostnames with fake domain name
                    anonymized_headers.append(header)

                else:
                    # Remove Received header
                    logging.debug(f"Removed Received header: {header}")
                    continue
            elif header.lower().startswith('x-mailer:'):
                if keep_x_mailer:
                    anonymized_headers.append(header)
                else:
                    logging.debug(f"Removed X-Mailer header: {header}")
                    continue
            elif header.lower().startswith('message-id:'):
                # Replace Message-ID
                anonymized_headers.append(f"Message-ID: <{fake.uuid4()}@{fake.domain_name()}>")
            elif header.lower().startswith('date:'):
                 #Replace Date header
                anonymized_headers.append(f"Date: {fake.date_time()}")
            elif header.lower().startswith('from:'):
                anonymized_headers.append(f"From: {fake.name()} <{fake.email()}>")
            elif header.lower().startswith('to:'):
                anonymized_headers.append(f"To: {fake.name()} <{fake.email()}>")
            elif header.lower().startswith('reply-to:'):
                anonymized_headers.append(f"Reply-To: {fake.name()} <{fake.email()}>")


            else:
                anonymized_headers.append(header)

        # Join the anonymized headers and add the body
        anonymized_email = '\n'.join(anonymized_headers) + header_end_marker + body_part

        # Write the anonymized email to the output file
        with open(output_file, 'w', encoding=encoding) as f:
            f.write(anonymized_email)

        logging.info(f"Anonymized email saved to {output_file}")

    except FileNotFoundError:
        logging.error(f"Error: Input file '{input_file}' not found.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

def main():
    """
    Main function to execute the email header anonymizer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(args.log_level.upper())

    # Validate input file existence
    if not os.path.exists(args.input_file):
        logging.error(f"Input file '{args.input_file}' does not exist.")
        sys.exit(1)
    
    anonymize_email_headers(args.input_file, args.output_file, args.keep_x_mailer, args.obfuscate_received)

if __name__ == "__main__":
    main()