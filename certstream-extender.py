import os
import re
import sys
import time
import logging
import sqlite3
import argparse
import certstream

from multiprocessing import Process, Queue
from signal import signal, SIGPIPE, SIG_DFL

def _storage_process(storage_queue, output_folder):
    """a function to process a queue output all content to a sqlite database"""
    # create and setup a new sqlite database on disk
    db_path = f'{output_folder}{os.sep}certstream-database.sqlite'
    db_connection = sqlite3.connect(db_path)
    db_cursor = db_connection.cursor()
    db_cursor.execute('CREATE TABLE IF NOT EXISTS certificate_information (provider text, common_name text, domains text, timestamp text)')
    db_connection.commit()

    logging.debug('the storage process is using the database at %s' % db_path)

    # process the storage queue forever
    while True:
        # retrieve and unpack the certificate tuple
        (cert_provider, cert_cn, cert_domains) = storage_queue.get()

        # check if a certificate has been seen before
        db_cursor.execute('SELECT timestamp FROM certificate_information WHERE provider = ? AND common_name = ? AND domains = ?', (cert_provider,cert_cn,cert_domains))
        record_exists = db_cursor.fetchone()

        # add unknown certificates to the database
        if record_exists is None:
            db_cursor.execute('INSERT INTO certificate_information VALUES(?,?,?,?)', (cert_provider,cert_cn,cert_domains,time.time()))
            db_connection.commit()
        # ignore previously discovered certificates
        else:
            logging.debug('Seen domain [%s] before, diregarding it' % cert_cn)

def _monitor_process(monitor_queue, output_folder, regular_expression):
    """a function to process a queue and log all domains matching the provided regular expression(s)"""
    compiled_regex = re.compile(regular_expression)

    # open a file to write alerts for the lifetime of the process
    with open(f'{output_folder}{os.sep}certstream-monitor-{time.time()}.txt', 'w') as output_file:
        logging.debug('The monitor process is writing to the file at %s' % output_file.name)

        # process the monitoring queue forever
        while True:
            # retrieve and unpack the certificate tuple
            (cert_provider, cert_cn, cert_domains) = monitor_queue.get()

            # if a match is discovered, write all domains associated with the certificate to a flat file
            if compiled_regex.match(cert_domains):
                output_file.write(cert_domains + '\n')

def _validate_directory(path):
    """an argparse validator to confirm user input is a valid directory"""
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f'cannot find directory {path}')

def main():
    parser = argparse.ArgumentParser(description='An extension for certstream allowing for output to disk and monitoring of the stream', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-o', dest='output_directory', type=_validate_directory, default=os.getcwd(), help='the output directory logs, alerts, and certificate information')
    parser.add_argument('-v', dest='logging_level', action='store_const', const=logging.DEBUG, default=logging.INFO, help='enable debug logging')
    parser.add_argument('-u', dest='url', default="wss://certstream.calidog.io", help='Connect to a certstream server.')

    storage_group = parser.add_argument_group('certificate storage', 'options related to outputting the certificate stream to disk')
    storage_group.add_argument('-s', dest='storage_stream', action='store_true', default=False, help='enable storage of the stream')

    monitor_group = parser.add_argument_group('certificate monitoring', 'options related to monitoring the certificate stream for domains of importance')
    monitor_group.add_argument('-m', dest='monitor_stream', action='store_true', default=False, help='enable custom monitoring of the stream')
    monitor_group.add_argument('-r', dest='monitor_regex', default='.+nl$|.+uk$', help='series of regular expressions joined by a |')

    cli_args = parser.parse_args()

    # setup logging
    logging.basicConfig(format='%(levelname)-8s %(message)s', level=cli_args.logging_level)

    # ignore broken pipes
    signal(SIGPIPE, SIG_DFL)

    def _process_certificate(message, context):
        data_source = message['data']['source']['name']
        certificate_cn = message['data']['leaf_cert']['subject']['CN']
        certificate_domains = '|'.join(message['data']['leaf_cert']['all_domains'])
        message_tuple = (data_source, certificate_cn, certificate_domains)

        if cli_args.storage_stream: storage_queue.put(message_tuple)
        if cli_args.monitor_stream: monitor_queue.put(message_tuple)

    # storage process
    if cli_args.storage_stream:
        storage_queue = Queue()
        storage_process = Process(target=_storage_process, daemon=True, args=(storage_queue,cli_args.output_directory))
        storage_process.start()
        logging.info('starting storage process with PID %s', storage_process.pid)

    # monitor process
    if cli_args.monitor_stream:
        monitor_queue = Queue()
        monitor_process = Process(target=_monitor_process, daemon=True, args=(monitor_queue,cli_args.output_directory,cli_args.monitor_regex))
        monitor_process.start()
        logging.info('starting monitor process with PID %s', monitor_process.pid)

    # certstream callback
    certstream.listen_for_events(_process_certificate, cli_args.url, skip_heartbeats=True)

if __name__ == '__main__':
    main()
