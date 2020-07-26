import os
import re
import sys
import time
import logging
import argparse
import certstream

from multiprocessing import Process, Queue
from signal import signal, SIGPIPE, SIG_DFL

def _storage_process(storage_queue, output_folder):
    """a function to process a queue output all content to a flat file"""
    with open(f'{output_folder}{os.sep}certstream-output-{time.time()}.txt', 'w') as output_file:
        logging.debug(f'Writing to file: {output_file.name}')
        
        while True:
            output_string = '|'.join(storage_queue.get())
            output_file.write(output_string + '\n')

def _monitor_process(monitor_queue, regular_expression):
    """a function to process a queue and log all domains matching the provided regular expression(s)"""
    compiled_regex = re.compile(regular_expression)

    while True:
        certificate_tuple = monitor_queue.get()
        (cert_provider, cert_cn, cert_domains) = certificate_tuple
        
        if compiled_regex.match(cert_cn):
            logging.info('found [%s] at [%s]', cert_cn, cert_provider)

def _validate_directory(path):
    """an argparse validator to confirm user input is a valid directory"""
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f'cannot find directory {path}')

def main():
    parser = argparse.ArgumentParser(description='An extension for certstream allowing for output to disk and monitoring of the stream', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-v', dest='logging_level', action='store_const', const=logging.DEBUG,
                        default=logging.INFO, help='enable debug logging')
    parser.add_argument('-u', dest='url', default="wss://certstream.calidog.io", help='Connect to a certstream server.')

    storage_group = parser.add_argument_group('certificate storage', 'options related to outputting the certificate stream to disk')
    storage_group.add_argument('-s', dest='storage_stream', action='store_true', default=False, help='enable storage of the stream')
    storage_group.add_argument('-o', dest='output_directory', type=_validate_directory, default=os.getcwd(), help='the output directory for the parsed feeds')

    monitor_group = parser.add_argument_group('certificate monitoring', 'options related to monitoring the certificate stream for domains of importance')
    monitor_group.add_argument('-m', dest='monitor_stream', action='store_true', default=False, help='enable custom monitoring of the stream')
    monitor_group.add_argument('-r', dest='monitor_regex', default='.+nl$|.+uk$', help='series of regular expressions joined by a |')

    cli_args = parser.parse_args()

    # setup logging
    logging.basicConfig(format='%(levelname)-8s %(message)s', level=cli_args.logging_level)

    # ignore broken pipes
    signal(SIGPIPE, SIG_DFL)

    def handle_certificates(message, context):
        data_source = message['data']['source']['name']
        certificate_cn = message['data']['leaf_cert']['subject']['CN']
        certificate_domains = ','.join(message['data']['leaf_cert']['all_domains'])
        message_tuple = (data_source, certificate_cn, certificate_domains)

        if cli_args.storage_stream: storage_queue.put(message_tuple)
        if cli_args.monitor_stream: monitor_queue.put(message_tuple)

    # storage process
    if cli_args.storage_stream:
        storage_queue = Queue()
        storage_process = Process(target=_storage_process, daemon=True, args=(storage_queue,cli_args.output_directory,))
        storage_process.start()
        logging.info('starting storage process with PID %s', storage_process.pid)

    # monitor process
    if cli_args.monitor_stream:
        monitor_queue = Queue()
        monitor_process = Process(target=_monitor_process, daemon=True, args=(monitor_queue,cli_args.monitor_regex,))
        monitor_process.start()
        logging.info('starting monitor process with PID %s', monitor_process.pid)

    # certstream callback
    certstream.listen_for_events(handle_certificates, cli_args.url, skip_heartbeats=True)

if __name__ == '__main__':
    main()
