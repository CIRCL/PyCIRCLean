import os
from datetime import datetime


def save_logs(groomer, test_description):
    divider = ('=' * 10 + '{}' + '=' * 10 + '\n')
    test_log_path = 'tests/test_logs/{}.log'.format(test_description)
    time_now = str(datetime.now().time()) + '\n'
    with open(test_log_path, 'wb+') as test_log:
        log_header = divider.format('TEST LOG')
        test_log.write(bytes(log_header, encoding='utf-8'))
        test_log.write(bytes(time_now, encoding='utf-8'))
        test_log.write(bytes(test_description, encoding='utf-8'))
        test_log.write(b'\n')
        test_log.write(b'-' * 20 + b'\n')
        with open(groomer.logger.log_path, 'rb') as logfile:
            log = logfile.read()
            test_log.write(log)
        if os.path.exists(groomer.logger.log_debug_err):
            test_log.write(bytes(divider.format('ERR LOG'), encoding='utf-8'))
            with open(groomer.logger.log_debug_err, 'rb') as debug_err:
                err = debug_err.read()
                test_log.write(err)
        if os.path.exists(groomer.logger.log_debug_out):
            test_log.write(bytes(divider.format('OUT LOG'), encoding='utf-8'))
            with open(groomer.logger.log_debug_out, 'rb') as debug_out:
                out = debug_out.read()
                test_log.write(out)
