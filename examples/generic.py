#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import mimetypes
import shlex
import subprocess
import time

from kittengroomer import FileBase, KittenGroomerBase, main

UNOCONV = '/usr/bin/unoconv'
LIBREOFFICE = '/usr/bin/libreoffice'
GS = '/usr/bin/gs'
PDF2HTMLEX = '/usr/bin/pdf2htmlEX'
SEVENZ = '/usr/bin/7z'


# Prepare application/<subtype>
mimes_office = ['msword', 'vnd.openxmlformats-officedocument.', 'vnd.ms-',
                'vnd.oasis.opendocument']
mimes_pdf = ['pdf', 'postscript']
mimes_xml = ['xml']
mimes_ms = ['x-dosexec']
mimes_compressed = ['zip', 'x-rar', 'x-bzip2', 'x-lzip', 'x-lzma', 'x-lzop',
                    'x-xz', 'x-compress', 'x-gzip', 'x-tar', 'compressed']
mimes_data = ['octet-stream']

# Aliases
aliases = {
    # Win executables
    'application/x-msdos-program': 'application/x-dosexec',
    'application/x-dosexec': 'application/x-msdos-program'
}

# Sometimes, mimetypes.guess_type is giving unexpected results, such as for the .tar.gz files:
# In [12]: mimetypes.guess_type('toot.tar.gz', strict=False)
# Out[12]: ('application/x-tar', 'gzip')
# It works as expected if you do mimetypes.guess_type('application/gzip', strict=False)
propertype = {'.gz': 'application/gzip'}


class File(FileBase):

    def __init__(self, src_path, dst_path):
        ''' Init file object, set the mimetype '''
        super(File, self).__init__(src_path, dst_path)

        self.is_recursive = False
        if not self.has_mimetype():
            # No mimetype, should not happen.
            self.make_dangerous()

        if self.is_dangerous():
            return

        self.log_details.update({'maintype': self.main_type,
                                 'subtype': self.sub_type,
                                 'extension': self.extension})

        # If the mimetype matches as text/*, it will be sent to LibreOffice, no need to cross check the mime/ext
        if self.main_type == 'text':
            return

        # Check correlation known extension => actual mime type
        if propertype.get(self.extension) is not None:
            expected_mimetype = propertype.get(self.extension)
        else:
            expected_mimetype, encoding = mimetypes.guess_type(self.src_path, strict=False)
            if aliases.get(expected_mimetype) is not None:
                expected_mimetype = aliases.get(expected_mimetype)

        is_known_extension = self.extension in mimetypes.types_map.keys()
        if is_known_extension and expected_mimetype != self.mimetype:
            self.log_details.update({'expected_mimetype': expected_mimetype})
            self.make_dangerous()

        # check correlation actual mime type => known extensions
        if aliases.get(self.mimetype) is not None:
            mimetype = aliases.get(self.mimetype)
        else:
            mimetype = self.mimetype
        expected_extensions = mimetypes.guess_all_extensions(mimetype, strict=False)
        if expected_extensions:
            if len(self.extension) > 0 and self.extension not in expected_extensions:
                self.log_details.update({'expected_extensions': expected_extensions})
                self.make_dangerous()
        else:
            # there are no known extensions associated to this mimetype.
            pass


class KittenGroomer(KittenGroomerBase):

    def __init__(self, root_src=None, root_dst=None, max_recursive=2, debug=False):
        '''
            Initialize the basics of the conversion process
        '''
        if root_src is None:
            root_src = os.path.join(os.sep, 'media', 'src')
        if root_dst is None:
            root_dst = os.path.join(os.sep, 'media', 'dst')
        super(KittenGroomer, self).__init__(root_src, root_dst, debug)

        self.recursive = 0
        self.max_recursive = max_recursive

        subtypes_apps = [
            (mimes_office, self._office_related),
            (mimes_pdf, self._pdf),
            (mimes_xml, self._office_related),
            (mimes_ms, self._executables),
            (mimes_compressed, self._archive),
            (mimes_data, self._binary_app),
        ]
        self.subtypes_application = self._init_subtypes_application(subtypes_apps)

        self.mime_processing_options = {
            'text': self.text,
            'audio': self.audio,
            'image': self.image,
            'video': self.video,
            'application': self.application,
            'example': self.example,
            'message': self.message,
            'model': self.model,
            'multipart': self.multipart,
            'inode': self.inode,
        }

        unoconv_listener = UNOCONV + ' --listener'
        self._run_process(unoconv_listener, background=True)

    # ##### Helpers #####
    def _init_subtypes_application(self, subtypes_application):
        '''
            Create the Dict to pick the right function based on the sub mime type
        '''
        to_return = {}
        for list_subtypes, fct in subtypes_application:
            for st in list_subtypes:
                to_return[st] = fct
        return to_return

    def _print_log(self):
        '''
            Print the logs related to the current file being processed
        '''
        tmp_log = self.log_name.fields(**self.cur_file.log_details)
        if self.cur_file.is_dangerous():
            tmp_log.warning(self.cur_file.log_string)
        elif self.cur_file.log_details.get('unknown') or self.cur_file.log_details.get('binary'):
            tmp_log.info(self.cur_file.log_string)
        else:
            tmp_log.debug(self.cur_file.log_string)

    def _run_process(self, command_line, timeout=0, background=False):
        '''Run subprocess, wait until it finishes'''
        if timeout != 0:
            deadline = time.time() + timeout
        else:
            deadline = None
        args = shlex.split(command_line)
        with open(self.log_debug_err, 'ab') as stderr, open(self.log_debug_out, 'ab') as stdout:
            p = subprocess.Popen(args, stdout=stdout, stderr=stderr)
        if background:
            # FIXME: This timer is here to make sure the unoconv listener is properly started.
            time.sleep(10)
            return True
        while True:
            code = p.poll()
            if code is not None:
                break
            if deadline is not None and time.time() > deadline:
                p.kill()
                break
            time.sleep(1)
        return True

    #######################

    # ##### Discarded mime types, reason in the comments ######
    def inode(self):
        ''' Usually empty file. No reason (?) to copy it on the dest key'''
        self.cur_file.log_string += 'Inode file'

    def unknown(self):
        ''' This main type is unknown, that should not happen '''
        self.cur_file.log_string += 'Unknown file'

    def example(self):
        '''Used in examples, should never be returned by libmagic'''
        self.cur_file.log_string += 'Example file'

    def multipart(self):
        '''Used in web apps, should never be returned by libmagic'''
        self.cur_file.log_string += 'Multipart file'

    # ##### Threated as malicious, no reason to have it on a USB key ######
    def message(self):
        '''Way to process message file'''
        self.cur_file.log_string += 'Message file'
        self.cur_file.make_dangerous()
        self._safe_copy()

    def model(self):
        '''Way to process model file'''
        self.cur_file.log_string += 'Model file'
        self.cur_file.make_dangerous()
        self._safe_copy()

    # ##### Converted ######
    def text(self):
        ''' LibreOffice should be able to open all the files '''
        self.cur_file.log_string += 'Text file'
        self._office_related()

    def application(self):
        ''' Everything can be there, using the subtype to decide '''
        for subtype, fct in list(self.subtypes_application.items()):
            if subtype in self.cur_file.sub_type:
                fct()
                self.cur_file.log_string += 'Application file'
                return
        self.cur_file.log_string += 'Unknown Application file'
        self._unknown_app()

    def _executables(self):
        '''Way to process executable file'''
        self.cur_file.add_log_details('processing_type', 'executable')
        self.cur_file.make_dangerous()
        self._safe_copy()

    def _office_related(self):
        '''Way to process all the files LibreOffice can handle'''
        self.cur_file.add_log_details('processing_type', 'office')
        dst_dir, filename = os.path.split(self.cur_file.dst_path)
        tmpdir = os.path.join(dst_dir, 'temp')
        name, ext = os.path.splitext(filename)
        tmppath = os.path.join(tmpdir, name + '.pdf')
        self._safe_mkdir(tmpdir)
        lo_command = '{} --format pdf -eSelectPdfVersion=1 --output "{}" "{}"'.format(
            UNOCONV, tmppath, self.cur_file.src_path)
        self._run_process(lo_command)
        self._pdfa(tmppath)
        self._safe_rmtree(tmpdir)

    def _pdfa(self, tmpsrcpath):
        '''Way to process PDF/A file'''
        pdf_command = '{} --dest-dir / "{}" "{}"'.format(PDF2HTMLEX, tmpsrcpath, self.cur_file.dst_path + '.html')
        self._run_process(pdf_command)

    def _pdf(self):
        '''Way to process PDF file'''
        self.cur_file.add_log_details('processing_type', 'pdf')
        dst_dir, filename = os.path.split(self.cur_file.dst_path)
        tmpdir = os.path.join(dst_dir, 'temp')
        tmppath = os.path.join(tmpdir, filename)
        self._safe_mkdir(tmpdir)
        # The magic comes from here: http://svn.ghostscript.com/ghostscript/trunk/gs/doc/Ps2pdf.htm#PDFA
        curdir = os.getcwd()
        os.chdir(self.resources_path)
        gs_command = '{} -dPDFA -dQUIET -dSAFER -dBATCH -dNOPAUSE -dNOOUTERSAVE -sProcessColorModel=DeviceCMYK -sDEVICE=pdfwrite -sPDFACompatibilityPolicy=1 -sOutputFile="{}" ./PDFA_def.ps "{}"'.format(
            GS, os.path.join(curdir, tmppath), os.path.join(curdir, self.cur_file.src_path))
        self._run_process(gs_command)
        os.chdir(curdir)
        self._pdfa(tmppath)
        self._safe_rmtree(tmpdir)

    def _archive(self):
        '''Way to process Archive'''
        self.cur_file.add_log_details('processing_type', 'archive')
        self.cur_file.is_recursive = True
        self.cur_file.log_string += 'Archive extracted, processing content.'
        tmpdir = self.cur_file.dst_path + '_temp'
        self._safe_mkdir(tmpdir)
        extract_command = '{} -p1 x "{}" -o"{}" -bd -aoa'.format(SEVENZ, self.cur_file.src_path, tmpdir)
        self._run_process(extract_command)
        self.recursive += 1
        self.tree(tmpdir)
        self.processdir(tmpdir, self.cur_file.dst_path)
        self.recursive -= 1
        self._safe_rmtree(tmpdir)

    def _unknown_app(self):
        '''Way to process an unknown file'''
        self.cur_file.make_unknown()
        self._safe_copy()

    def _binary_app(self):
        '''Way to process an unknown binary file'''
        self.cur_file.make_binary()
        self._safe_copy()

    #######################

    # ##### Not converted, checking the mime type ######
    def audio(self):
        '''Way to process an audio file'''
        self.cur_file.log_string += 'Audio file'
        self._media_processing()

    def image(self):
        '''Way to process an image'''
        self.cur_file.log_string += 'Image file'
        self._media_processing()

    def video(self):
        '''Way to process a video'''
        self.cur_file.log_string += 'Video file'
        self._media_processing()

    def _media_processing(self):
        '''Generic way to process all the media files'''
        self.cur_file.add_log_details('processing_type', 'media')
        self._safe_copy()

    #######################

    def processdir(self, src_dir=None, dst_dir=None):
        '''
            Main function doing the processing
        '''
        if src_dir is None:
            src_dir = self.src_root_dir
        if dst_dir is None:
            dst_dir = self.dst_root_dir

        if self.recursive > 0:
            self._print_log()

        if self.recursive >= self.max_recursive:
            self.cur_file.make_dangerous()
            self.cur_file.add_log_details('Archive Bomb', True)
            self.log_name.warning('ARCHIVE BOMB.')
            self.log_name.warning('The content of the archive contains recursively other archives.')
            self.log_name.warning('This is a bad sign so the archive is not extracted to the destination key.')
            self._safe_rmtree(src_dir)
            if src_dir.endswith('_temp'):
                archbomb_path = src_dir[:-len('_temp')]
                self._safe_remove(archbomb_path)

        for srcpath in self._list_all_files(src_dir):
            self.cur_file = File(srcpath, srcpath.replace(src_dir, dst_dir))

            self.log_name.info('Processing {} ({}/{})', srcpath.replace(src_dir + '/', ''),
                               self.cur_file.main_type, self.cur_file.sub_type)
            if not self.cur_file.is_dangerous():
                self.mime_processing_options.get(self.cur_file.main_type, self.unknown)()
            else:
                self._safe_copy()
            if not self.cur_file.is_recursive:
                self._print_log()

if __name__ == '__main__':
    main(KittenGroomer, 'Generic version of the KittenGroomer. Convert and rename files.')
