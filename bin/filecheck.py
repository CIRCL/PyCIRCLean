#!/usr/bin/env python
# -*- coding: utf-8 -*-
import magic
import os
import mimetypes
import shlex
import subprocess
import time

import oletools.oleid
import olefile
import officedissector

from pdfid import PDFiD, cPDFiD

from kittengroomer import FileBase, KittenGroomerBase, main

SEVENZ = '/usr/bin/7z'


# Prepare application/<subtype>
mimes_ooxml = ['vnd.openxmlformats-officedocument.']
mimes_office = ['msword', 'vnd.ms-']
mimes_libreoffice = ['vnd.oasis.opendocument']
mimes_rtf = ['rtf', 'richtext']
mimes_pdf = ['pdf', 'postscript']
mimes_xml = ['xml']
mimes_ms = ['dosexec']
mimes_compressed = ['zip', 'rar', 'bzip2', 'lzip', 'lzma', 'lzop',
                    'xz', 'compress', 'gzip', 'tar']
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

        mimetype = magic.from_file(src_path, mime=True).decode("utf-8")
        self.main_type, self.sub_type = mimetype.split('/')
        a, self.extension = os.path.splitext(src_path)
        self.is_recursive = False

        self.log_details.update({'maintype': self.main_type, 'subtype': self.sub_type, 'extension': self.extension})
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
        if is_known_extension and expected_mimetype != mimetype:
            self.log_details.update({'expected_mimetype': expected_mimetype})
            self.make_dangerous()

        # check correlation actual mime type => known extensions
        if aliases.get(mimetype) is not None:
            mimetype = aliases.get(mimetype)
        expected_extensions = mimetypes.guess_all_extensions(mimetype, strict=False)
        if expected_extensions is not None:
            if len(self.extension) > 0 and self.extension not in expected_extensions:
                self.log_details.update({'expected_extensions': expected_extensions})
                self.make_dangerous()
        else:
            # there are no known extensions associated to this mimetype.
            pass


class KittenGroomerFileCheck(KittenGroomerBase):

    def __init__(self, root_src=None, root_dst=None, max_recursive=5):
        '''
            Initialize the basics of the conversion process
        '''
        if root_src is None:
            root_src = os.path.join(os.sep, 'media', 'src')
        if root_dst is None:
            root_dst = os.path.join(os.sep, 'media', 'dst')
        super(KittenGroomerFileCheck, self).__init__(root_src, root_dst)

        self.recursive = 0
        self.max_recursive = max_recursive

        subtypes_apps = [
            (mimes_office, self._winoffice),
            (mimes_ooxml, self._ooxml),
            (mimes_rtf, self.text),
            (mimes_libreoffice, self._libreoffice),
            (mimes_pdf, self._pdf),
            (mimes_xml, self.text),
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
        if self.cur_file.log_details.get('dangerous'):
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
        p = subprocess.Popen(args)
        if background:
            # This timer is here to make sure the unoconv listener is properly started.
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

    # ##### Threated as malicious, no reason to have it on a USB key ######
    def example(self):
        '''Way to process example file'''
        self.cur_file.log_string += 'Example file'
        self.cur_file.make_dangerous()
        self._safe_copy()

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

    def multipart(self):
        '''Way to process multipart file'''
        self.cur_file.log_string += 'Multipart file'
        self.cur_file.make_dangerous()
        self._safe_copy()

    #######################

    # ##### Converted ######
    def text(self):
        ''' LibreOffice should be able to open all the files '''
        for r in mimes_rtf:
            if r in self.cur_file.sub_type:
                self.cur_file.log_string += 'Rich Text file'
                # TODO: need a way to convert it to plain text
                self.cur_file.force_ext('.txt')
                self._safe_copy()
        else:
            self.cur_file.log_string += 'Text file'
            self.cur_file.force_ext('.txt')
            self._safe_copy()

    def application(self):
        ''' Everything can be there, using the subtype to decide '''
        for subtype, fct in self.subtypes_application.items():
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

    def _winoffice(self):
        self.cur_file.add_log_details('processing_type', 'WinOffice')
        # Try as if it is a valid document
        oid = oletools.oleid.OleID(self.cur_file.src_path)
        if not olefile.isOleFile(self.cur_file.src_path):
            # Manual processing, may already count as suspicious
            try:
                ole = olefile.OleFileIO(self.cur_file.src_path, raise_defects=olefile.DEFECT_INCORRECT)
            except:
                self.cur_file.add_log_details('not_parsable', True)
                self.cur_file.make_dangerous()
            if ole.parsing_issues:
                self.cur_file.add_log_details('parsing_issues', True)
                self.cur_file.make_dangerous()
            else:
                if ole.exists('macros/vba') or ole.exists('Macros') \
                        or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                    self.cur_file.add_log_details('macro', True)
                    self.cur_file.make_dangerous()
        else:
            indicators = oid.check()
            # Encrypted ban be set by multiple checks on the script
            if oid.encrypted.value:
                self.cur_file.add_log_details('encrypted', True)
                self.cur_file.make_dangerous()
            if oid.macros.value or oid.ole.exists('macros/vba') or oid.ole.exists('Macros') \
                    or oid.ole.exists('_VBA_PROJECT_CUR') or oid.ole.exists('VBA'):
                self.cur_file.add_log_details('macro', True)
                self.cur_file.make_dangerous()
            for i in indicators:
                if i._id == 'ObjectPool' and i.value:
                    # FIXME: Is it suspicious?
                    self.cur_file.add_log_details('objpool', True)
                elif i._id == 'flash' and i.value:
                    self.cur_file.add_log_details('flash', True)
                    self.cur_file.make_dangerous()
        self._safe_copy()

    def _ooxml(self):
        self.cur_file.add_log_details('processing_type', 'ooxml')
        doc = officedissector.doc.Document(self.cur_file.src_path)
        # There are probably other potentially malicious features:
        # fonts, custom props, custom XML
        if doc.is_macro_enabled or len(doc.features.macros) > 0:
            self.cur_file.add_log_details('macro', True)
            self.cur_file.make_dangerous()
        if len(doc.features.embedded_controls) > 0:
            self.cur_file.add_log_details('activex', True)
            self.cur_file.make_dangerous()
        if len(doc.features.embedded_objects) > 0:
            # Exploited by CVE-2014-4114 (OLE)
            self.cur_file.add_log_details('embedded_obj', True)
            self.cur_file.make_dangerous()
        if len(doc.features.embedded_packages) > 0:
            self.cur_file.add_log_details('embedded_pack', True)
            self.cur_file.make_dangerous()
        self._safe_copy()

    def _libreoffice(self):
        self.cur_file.add_log_details('processing_type', 'libreoffice')
        # As long as there ar no way to do a sanity check on the files => dangerous
        self.cur_file.make_dangerous()
        self._safe_copy()

    def _pdf(self):
        '''Way to process PDF file'''
        self.cur_file.add_log_details('processing_type', 'pdf')
        xmlDoc = PDFiD(self.cur_file.src_path)
        oPDFiD = cPDFiD(xmlDoc)
        # TODO: other keywords?
        if oPDFiD.encrypt > 0:
            self.cur_file.add_log_details('encrypted', True)
            self.cur_file.make_dangerous()
        if oPDFiD.js > 0 or oPDFiD.javascript > 0:
            self.cur_file.add_log_details('javascript', True)
            self.cur_file.make_dangerous()
        if oPDFiD.aa > 0 or oPDFiD.openaction > 0:
            self.cur_file.add_log_details('openaction', True)
            self.cur_file.make_dangerous()
        if oPDFiD.richmedia > 0:
            self.cur_file.add_log_details('flash', True)
            self.cur_file.make_dangerous()
        if oPDFiD.launch > 0:
            self.cur_file.add_log_details('launch', True)
            self.cur_file.make_dangerous()

    def _archive(self):
        '''Way to process Archive'''
        self.cur_file.add_log_details('processing_type', 'archive')
        self.cur_file.is_recursive = True
        self.cur_file.log_string += 'Archive extracted, processing content.'
        tmpdir = self.cur_file.dst_path + '_temp'
        self._safe_mkdir(tmpdir)
        extract_command = '{} -p1 x {} -o{} -bd -aoa'.format(SEVENZ, self.cur_file.src_path, tmpdir)
        self._run_process(extract_command)
        self.recursive += 1
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
            self.cur_log.warning('ARCHIVE BOMB.')
            self.cur_log.warning('The content of the archive contains recursively other archives.')
            self.cur_log.warning('This is a bad sign so the archive is not extracted to the destination key.')
            self._safe_rmtree(src_dir)
            if src_dir.endswith('_temp'):
                archbomb_path = src_dir[:-len('_temp')]
                self._safe_remove(archbomb_path)

        for srcpath in self._list_all_files(src_dir):
            self.cur_file = File(srcpath, srcpath.replace(src_dir, dst_dir))

            self.log_name.info('Processing {} ({}/{})', srcpath.replace(src_dir + '/', ''),
                               self.cur_file.main_type, self.cur_file.sub_type)
            if self.cur_file.log_details.get('dangerous') is None:
                self.mime_processing_options.get(self.cur_file.main_type, self.unknown)()
            else:
                self._safe_copy()
            if not self.cur_file.is_recursive:
                self._print_log()

if __name__ == '__main__':
    main(KittenGroomerFileCheck, 'Generic version of the KittenGroomer. Convert and rename files.')
