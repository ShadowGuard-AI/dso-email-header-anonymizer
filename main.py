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
    if os.path.realpath(input_file) == os.path.realpath(output_file) or os.path.abspath(input_file) == os.path.abspath(output_file):
        logging.error("Error: output file is the same as the input file; refusing to write in place.")
        return 1
    # Also compare resolved paths so spellings such as ./file are caught.
    try:
        from pathlib import Path
        if Path(input_file).resolve() == Path(output_file).resolve():
            logging.error("Error: output file is the same as the input file; refusing to write in place.")
            return 1
    except Exception:
        pass
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
                logging.error("Error: could not determine the header/body separator; no output written.")
                return 1

        header_part, body_part = email_content.split(header_end_marker, 1)
        raw_headers = header_part.splitlines()
        # Unfold continuation lines (lines starting with space or tab)
        # into the header line they continue, before any handling.
        headers = []
        for raw_line in raw_headers:
            if raw_line[:1] in (' ', '\t') and headers:
                headers[-1] = headers[-1] + ' ' + raw_line.strip()
            else:
                headers.append(raw_line)

        anonymized_headers = []
        fake = Faker()
        anonymized_count = 0
        # The handled list below is the whole coverage, and its edges are
        # worth stating in one place: any header not named there passes
        # through byte for byte, including Subject, Return-Path,
        # Delivered-To, References, and X-Originating-IP, several of which
        # can carry the very addresses this tool replaces elsewhere. The
        # body is never looked at either, so a signature block in the body
        # keeps its names, addresses, and phone numbers through a
        # successful run.

        for header in headers:
            if header.lower().startswith('received:'):
                if obfuscate_received:
                    # Two shapes hide in these three substitutions. The
                    # email pass uses a callable, so each address gets its
                    # own fake; the IP and hostname passes take a plain
                    # string drawn once, so every IP in the header becomes
                    # the same fake IP and every hostname the same fake
                    # domain, which invents a sameness the original did
                    # not have. And because the hostname pass runs last,
                    # it also re-matches the domain inside the fake emails
                    # the first pass just wrote, and replaces that too.
                    header = re.sub(r'[\w.+-]+@[\w.-]+', lambda m: fake.email(), header)
                    ip_address_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                    header = re.sub(ip_address_pattern, fake.ipv4(), header)
                    hostname_pattern = r'(?<![\w.-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w.-])'
                    header = re.sub(hostname_pattern, fake.domain_name(), header)
                    anonymized_headers.append(header)
                    anonymized_count += 1

                else:
                    # Remove Received header
                    logging.debug(f"Removed Received header: {header}")
                    anonymized_count += 1
                    continue
            elif header.lower().startswith('x-mailer:'):
                if keep_x_mailer:
                    anonymized_headers.append(header)
                else:
                    logging.debug(f"Removed X-Mailer header: {header}")
                    anonymized_count += 1
                    continue
            elif header.lower().startswith('message-id:'):
                # Replace Message-ID
                anonymized_headers.append(f"Message-ID: <{fake.uuid4()}@{fake.domain_name()}>")
                anonymized_count += 1
            elif header.lower().startswith('date:'):
                 #Replace Date header
                anonymized_headers.append(f"Date: {fake.date_time()}")
                anonymized_count += 1
            elif header.lower().startswith('from:'):
                # Every address header below is rebuilt as exactly one
                # fake name and address, whatever the original held: a To
                # header naming five recipients becomes one invented
                # person, so the recipient count and any group structure
                # are lost, not just the identities. The Date replacement
                # above has its own cost: the fake datetime is printed in
                # Python's default shape, not the RFC date format a mail
                # reader expects in that header.
                anonymized_headers.append(f"From: {fake.name()} <{fake.email()}>")
                anonymized_count += 1
            elif header.lower().startswith('to:'):
                anonymized_headers.append(f"To: {fake.name()} <{fake.email()}>")
                anonymized_count += 1
            elif header.lower().startswith('cc:'):
                anonymized_headers.append(f"Cc: {fake.name()} <{fake.email()}>")
                anonymized_count += 1
            elif header.lower().startswith('bcc:'):
                anonymized_headers.append(f"Bcc: {fake.name()} <{fake.email()}>")
                anonymized_count += 1
            elif header.lower().startswith('sender:'):
                anonymized_headers.append(f"Sender: {fake.name()} <{fake.email()}>")
                anonymized_count += 1
            elif header.lower().startswith('x-original-from:'):
                anonymized_headers.append(f"X-Original-From: {fake.name()} <{fake.email()}>")
                anonymized_count += 1
            elif header.lower().startswith('reply-to:'):
                anonymized_headers.append(f"Reply-To: {fake.name()} <{fake.email()}>")
                anonymized_count += 1


            else:
                anonymized_headers.append(header)

        if anonymized_count == 0:
            logging.error("Error: no headers anonymized; no output written.")
            return 1

        # Join the anonymized headers and add the body
        anonymized_email = '\n'.join(anonymized_headers) + header_end_marker + body_part

        # Write the anonymized email to the output file
        with open(output_file, 'w', encoding=encoding) as f:
            f.write(anonymized_email)

        logging.info(f"Anonymized email saved to {output_file}")
        return 0

    except FileNotFoundError:
        logging.error(f"Error: Input file '{input_file}' not found.")
        return 1
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return 1

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
    
    result = anonymize_email_headers(args.input_file, args.output_file, args.keep_x_mailer, args.obfuscate_received)
    sys.exit(result if isinstance(result, int) else 0)

if __name__ == "__main__":
    main()