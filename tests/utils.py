import os

from datetime import datetime

import yaml


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


class SampleFile():
    def __init__(self, path, expect_dangerous):
        self.path = path
        self.expect_dangerous = expect_dangerous

    @property
    def expect_path(self):
        return self.path + '.expect'

    @property
    def has_expect_file(self):
        return os.path.isfile(self.expect_path)

    def parse_expect(self):
        with open(self.expect_path, 'r') as expect_file:
            self.expect_dict = yaml.safe_load(expect_file)
        self.expect_dangerous = self.expect_dict['expect_dangerous']
        self.groomer_needed = self.expect_dict['groomer_needed']
        self.expected_mimetype = self.expect_dict['expected_mimetype']
