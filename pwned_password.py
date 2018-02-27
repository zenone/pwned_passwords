#!/usr/bin/env python
# coding = utf-8
#
# Check to see if a password shows up on Troy Hunt's
# V2 update to Pwned Passwords, and if so, how many
# times.
#
# Todo: add exception handling


########################################
# Imports
import getpass
import logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
import hashlib
import requests
import sys


########################################
# Functions

def hash_password(password):
    '''
    Create a sha1 hash of the password.
    :param password: String passed in by the user to be hashed and sliced.
    :return dict: Return a python dict with the password hash and slices.
    '''
    sha_1 = hashlib.sha1()
    sha_1.update(password.encode('utf-8'))
    sha1_hexdigest = sha_1.hexdigest()
    sha1_prefix = sha1_hexdigest[0:5]
    sha1_suffix = sha1_hexdigest[5:]
    logging.debug('sha1_hexdigest: {0}'.format(sha1_hexdigest))
    logging.debug('sha1_prefix: {0}'.format(sha1_prefix))
    logging.debug('sha1_suffix: {0}'.format(sha1_suffix))
    return {'sha1_hexdigest': sha1_hexdigest,
            'sha1_prefix': sha1_prefix,
            'sha1_suffix': sha1_suffix}


def check_hash(hash_dict):
    '''
    Check hash against pwnedpasswords.com
    :param hash_dict: Python dict that has the hash and hash slices.
    :return dict: Return a python dict with the results of the check.
    '''
    base_url = 'https://api.pwnedpasswords.com/range/{0}'
    resp = requests.get(base_url.format(hash_dict['sha1_prefix']))
    logging.debug('status code: {0}'.format(resp.status_code))
    count = 0
    status = False
    if resp.status_code == 200:
        for line in resp.text.split('\n'):
            if hash_dict['sha1_suffix'].lower() in line.lower():
                status = True
                count = int(line.split(':')[1])
                logging.debug('password found')
                logging.debug('count: {0:,}'.format(count))
        if not status:
            logging.debug('password not found')
    else:
        logging.debug('error code {0}'.format(resp.status_code))
        print('[!] Error checking hash. Code: {0}'.format(resp.status_code))
        sys.exit(1)
    return {'status': status, 'count': count}


def main():
    '''
    Main function that orchestrates the magic.
    '''
    password = getpass.getpass('Enter password to check: ')

    # Hash the password
    hashed_pass = hash_password(password)
    print('[+] Sha1 hash: {0}'.format(hashed_pass['sha1_hexdigest']))

    # Check password hash against pwnedpasswords.com
    check_resp = check_hash(hashed_pass)

    # Display results
    if check_resp['status']:
        print(
            '[+] Password hash found. Count: {0:,}'.format(check_resp['count']))
    else:
        print('[-] Password hash not found.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
