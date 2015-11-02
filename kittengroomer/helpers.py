#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import shutil
from twiggy import quickSetup, log
import argparse


class KittenGroomerError(Exception):
    def __init__(self, message):
        '''
            Base KittenGroomer exception handler.
        '''
        super(KittenGroomerError, self).__init__(message)
        self.message = message


class ImplementationRequired(KittenGroomerError):
    '''
        Implementation required error
    '''
    pass


class FileBase(object):

    def __init__(self, src_path, dst_path):
        '''
            Contains base information for a file on the source USB key,
            initialised with expected src and dest path
        '''
        self.src_path = src_path
        self.dst_path = dst_path
        self.log_details = {'filepath': self.src_path}
        self.log_string = ''

    def add_log_details(self, key, value):
        '''
            Add an entry in the log dictionary
        '''
        self.log_details[key] = value

    def make_dangerous(self):
        '''
            This file should be considered as dangerous and never run.
            Prepending and appending DANGEROUS to the destination
            file name avoid double-click of death
        '''
        if self.log_details.get('dangerous'):
            # Already marked as dangerous, do nothing
            return
        self.log_details['dangerous'] = True
        path, filename = os.path.split(self.dst_path)
        self.dst_path = os.path.join(path, 'DANGEROUS_{}_DANGEROUS'.format(filename))

    def make_unknown(self):
        '''
            This file has an unknown type and it was not possible to take
            a decision. Theuser will have to decide what to do.
            Prepending UNKNOWN
        '''
        if self.log_details.get('dangerous') or self.log_details.get('binary'):
            # Already marked as dangerous or binary, do nothing
            return
        self.log_details['unknown'] = True
        path, filename = os.path.split(self.dst_path)
        self.dst_path = os.path.join(path, 'UNKNOWN_{}'.format(filename))

    def make_binary(self):
        '''
            This file is a binary, and should probably not be run.
            Appending .bin avoir double click of death but the user
            will have to decide by itself.
        '''
        if self.log_details.get('dangerous'):
            # Already marked as dangerous, do nothing
            return
        self.log_details['binary'] = True
        path, filename = os.path.split(self.dst_path)
        self.dst_path = os.path.join(path, '{}.bin'.format(filename))

    def force_ext(self, ext):
        if not self.dst_path.endswith(ext):
            self.log_details['force_ext'] = True
            self.dst_path += ext


class KittenGroomerBase(object):

    def __init__(self, root_src, root_dst):
        '''
            Setup the base options of the copy/convert setup
        '''
        self.src_root_dir = root_src
        self.dst_root_dir = root_dst
        self.log_root_dir = os.path.join(self.dst_root_dir, 'logs')
        self._safe_rmtree(self.log_root_dir)
        self._safe_mkdir(self.log_root_dir)
        self.log_processing = os.path.join(self.log_root_dir, 'processing.log')

        quickSetup(file=self.log_processing)
        self.log_name = log.name('files')
        self.ressources_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        os.environ["PATH"] += os.pathsep + self.ressources_path

        self.cur_file = None

    # ##### Helpers #####
    def _safe_rmtree(self, directory):
        '''Remove a directory tree if it exists'''
        if os.path.exists(directory):
            shutil.rmtree(directory)

    def _safe_remove(self, filepath):
        '''Remove a file if it exists'''
        if os.path.exists(filepath):
            os.remove(filepath)

    def _safe_mkdir(self, directory):
        '''Remove a directory if it exists'''
        if not os.path.exists(directory):
            os.makedirs(directory)

    def _safe_copy(self, src=None, dst=None):
        ''' Copy a file and create directory if needed '''
        if src is None:
            src = self.cur_file.src_path
        if dst is None:
            dst = self.cur_file.dst_path
        try:
            dst_path, filename = os.path.split(dst)
            self._safe_mkdir(dst_path)
            shutil.copy(src, dst)
            return True
        except Exception as e:
            # TODO: Logfile
            print(e)
            return False

    def _list_all_files(self, directory):
        ''' Generate an iterator over all the files in a directory tree '''
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                yield filepath

    def _print_log(self):
        '''
            Print log, should be called after each file.

            You probably want to reimplement it in the subclass
        '''
        tmp_log = self.log_name.fields(**self.cur_file.log_details)
        tmp_log.info('It did a thing.')

    #######################

    def processdir(self, src_dir=None, dst_dir=None):
        '''
            Main function doing the work, you have to implement it yourself.
        '''
        raise ImplementationRequired('You have to implement the result processdir.')


def main(kg_implementation, description='Call the KittenGroomer implementation to do things on files present in the source directory to the destination directory'):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.processdir()
