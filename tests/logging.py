import os


def save_logs(groomer, test_description):
    divider = ('=' * 10 + '{}' + '=' * 10 + '\n')
    test_log_path = 'tests/test_logs/{}.log'.format(test_description)
    with open(test_log_path, 'w+') as test_log:
        test_log.write(divider.format('TEST LOG'))
        with open(groomer.log_processing, 'r') as logfile:
            log = logfile.read()
            test_log.write(log)
        if groomer.debug:
            if os.path.exists(groomer.log_debug_err):
                test_log.write(divider.format('ERR LOG'))
                with open(groomer.log_debug_err, 'r') as debug_err:
                    err = debug_err.read()
                    test_log.write(err)
            if os.path.exists(groomer.log_debug_out):
                test_log.write(divider.format('OUT LOG'))
                with open(groomer.log_debug_out, 'r') as debug_out:
                    out = debug_out.read()
                    test_log.write(out)
