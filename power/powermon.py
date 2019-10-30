'''
Title: powermon
Author: Cary Williams
Email: cary@linux.com
Date: 10/30/2019
Description: pull each day's power usage from daily email,
             extract the day's usage (in kWh), and the
             cost of the day's service, and add to a plot to monitor usage.

Todo: extract data from email, add to plot, add tests

Author:  Cary Williams

'''

#!/usr/bin/env python

#import sys
import imaplib
import email
import datetime
from getpass import getpass

MAIL = imaplib.IMAP4_SSL('imap.gmail.com') # Set to server
FROM_EMAIL = "" # Enter email address or userID for mail server
FROM_PWD = getpass("Enter your password: ")


def process_mailbox(MAIL):
    ''' pulls messages and prints dates '''
    message, data = MAIL.search(None, "ALL")
    if message != 'OK':
        print "No messages found!"
        return

    for num in data[0].split():
        message, data = MAIL.fetch(num, '(RFC822)')
        if message != 'OK':
            print "ERROR getting message", num
            return

        msg = email.message_from_string(data[0][1])
        print 'Message %s: %s' % (num, msg['Subject'])
        date_tuple = email.utils.parsedate_tz(msg['Date'])
        if date_tuple:
            local_date = datetime.datetime.fromtimestamp(
                email.utils.mktime_tz(date_tuple))
            print "Local Date:", \
                local_date.strftime("%m-%d-%y")

try:
    MAIL.login(FROM_EMAIL, FROM_PWD)
    print "Connected to email server..."

    message, data = MAIL.select("POWER")
    if message == 'OK':
        print "Processing mailbox...\n"
        process_mailbox(MAIL) # ... do something with emails, see below ...
        MAIL.close()
    MAIL.logout()

except imaplib.IMAP4.error:
    print "LOGIN FAILED!!! "
    # ... exit or deal with failure...
