#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import mimetypes
import shlex
import subprocess
import zipfile
import argparse

import oletools.oleid
import olefile
import officedissector
import warnings
import exifread
from PIL import Image
# from PIL import PngImagePlugin
from pdfid import PDFiD, cPDFiD

from kittengroomer import FileBase, KittenGroomerBase


SEVENZ_PATH = '/usr/bin/7z'


class Config:
    # Application subtypes (mimetype: 'application/<subtype>')
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

    # Image subtypes
    mimes_exif = ['image/jpeg', 'image/tiff']
    mimes_png = ['image/png']

    # Mimetypes with metadata
    mimes_metadata = ['image/jpeg', 'image/tiff', 'image/png']

    # Commonly used malicious extensions
    # Sources: http://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows/
    # https://github.com/wiregit/wirecode/blob/master/components/core-settings/src/main/java/org/limewire/core/settings/FilterSettings.java
    malicious_exts = (
        # Applications
        ".exe", ".pif", ".application", ".gadget", ".msi", ".msp", ".com", ".scr",
        ".hta", ".cpl", ".msc", ".jar",
        # Scripts
        ".bat", ".cmd", ".vb", ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf",
        ".wsc", ".wsh", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2",
        ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
        # Shortcuts
        ".scf", ".lnk", ".inf",
        # Other
        ".reg", ".dll",
        # Office macro (OOXML with macro enabled)
        ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
        ".ppsm", ".sldm",
        # banned from wirecode
        ".asf", ".asx", ".au", ".htm", ".html", ".mht", ".vbs",
        ".wax", ".wm", ".wma", ".wmd", ".wmv", ".wmx", ".wmz", ".wvx",
    )

    # Aliases
    aliases = {
        # Win executables
        'application/x-msdos-program': 'application/x-dosexec',
        'application/x-dosexec': 'application/x-msdos-program',
        # Other apps with confusing mimetypes
        'application/rtf': 'text/rtf',
    }

    # Sometimes, mimetypes.guess_type gives unexpected results, such as for .tar.gz files:
    # In [12]: mimetypes.guess_type('toot.tar.gz', strict=False)
    # Out[12]: ('application/x-tar', 'gzip')
    # It works as expected if you do mimetypes.guess_type('application/gzip', strict=False)
    override_ext = {'.gz': 'application/gzip'}


class File(FileBase):

    def __init__(self, src_path, dst_path, logger):
        super(File, self).__init__(src_path, dst_path, logger)
        self.is_recursive = False
        self.log_details.update({'maintype': self.main_type,
                                 'subtype': self.sub_type,
                                 'extension': self.extension})

        subtypes_apps = [
            (Config.mimes_office, self._winoffice),
            (Config.mimes_ooxml, self._ooxml),
            (Config.mimes_rtf, self.text),
            (Config.mimes_libreoffice, self._libreoffice),
            (Config.mimes_pdf, self._pdf),
            (Config.mimes_xml, self.text),
            (Config.mimes_ms, self._executables),
            (Config.mimes_compressed, self._archive),
            (Config.mimes_data, self._binary_app),
        ]
        self.app_subtype_methods = self._make_method_dict(subtypes_apps)

        types_metadata = [
            (Config.mimes_exif, self._metadata_exif),
            (Config.mimes_png, self._metadata_png),
        ]
        self.metadata_mimetype_methods = self._make_method_dict(types_metadata)

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

    def _check_dangerous(self):
        if not self.has_mimetype():  # No mimetype, should not happen.
            self.make_dangerous()
        if not self.has_extension():
            self.make_dangerous()
        if self.extension in Config.malicious_exts:
            self.log_details.update({'malicious_extension': self.extension})
            self.make_dangerous()

    def _check_extension(self):
        """Guesses the file's mimetype based on its extension. If the file's
        mimetype (as determined by libmagic) is contained in the mimetype
        module's list of valid mimetypes and the expected mimetype based on its
        extension differs from the mimetype determined by libmagic, then it
        marks the file as dangerous."""
        if self.extension in Config.override_ext:
            expected_mimetype = Config.override_ext[self.extension]
        else:
            expected_mimetype, encoding = mimetypes.guess_type(self.src_path,
                                                               strict=False)
            if expected_mimetype in Config.aliases:
                expected_mimetype = Config.aliases[expected_mimetype]
        is_known_extension = self.extension in mimetypes.types_map.keys()
        if is_known_extension and expected_mimetype != self.mimetype:
            self.log_details.update({'expected_mimetype': expected_mimetype})
            self.make_dangerous()

    def _check_mimetype(self):
        """Takes the mimetype (as determined by libmagic) and determines
        whether the list of extensions that are normally associated with
        that extension contains the file's actual extension."""
        if self.mimetype in Config.aliases:
            mimetype = Config.aliases[self.mimetype]
        else:
            mimetype = self.mimetype
        expected_extensions = mimetypes.guess_all_extensions(mimetype,
                                                             strict=False)
        if expected_extensions:
            if self.has_extension() and self.extension not in expected_extensions:
                self.log_details.update({'expected_extensions': expected_extensions})
                self.make_dangerous()

    def check(self):
        self._check_dangerous()
        self._check_extension()
        self._check_mimetype()
        if not self.is_dangerous():
            self.mime_processing_options.get(self.main_type, self.unknown)()

    # ##### Helper functions #####
    def _make_method_dict(self, list_of_tuples):
        """Returns a dictionary with mimetype: method pairs."""
        dict_to_return = {}
        for list_of_subtypes, method in list_of_tuples:
            for subtype in list_of_subtypes:
                dict_to_return[subtype] = method
        return dict_to_return

    def write_log(self):
        """Print the logs related to the current file being processed."""
        # TODO: move to helpers?
        tmp_log = self.logger.log.fields(**self.log_details)
        if self.is_dangerous():
            tmp_log.warning(self.log_string)
        elif self.log_details.get('unknown') or self.log_details.get('binary'):
            tmp_log.info(self.log_string)
        else:
            tmp_log.debug(self.log_string)

    # Make this an @property
    def has_metadata(self):
        if self.mimetype in Config.mimes_metadata:
            return True
        return False

    def _run_process(self, command_string, timeout=None):
        """Run command_string in a subprocess, wait until it finishes."""
        args = shlex.split(command_string)
        with open(self.logger.log_debug_err, 'ab') as stderr, open(self.logger.log_debug_out, 'ab') as stdout:
            try:
                subprocess.check_call(args, stdout=stdout, stderr=stderr, timeout=timeout)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                return
        return True

    def _make_tempdir(self):
        """Make a temporary directory."""
        self.tempdir_path = self.dst_path + '_temp'
        if not os.path.exists(self.tempdir_path):
            os.makedirs(self.tempdir_path)
        return self.tempdir_path

    #######################
    # ##### Discarded mimetypes, reason in the docstring ######
    def inode(self):
        """Empty file or symlink."""
        if self.is_symlink():
            self.log_string += 'Symlink to {}'.format(self.log_details['symlink'])
        else:
            self.log_string += 'Inode file'

    def unknown(self):
        """Main type should never be unknown."""
        self.log_string += 'Unknown file'

    def example(self):
        """Used in examples, should never be returned by libmagic."""
        self.log_string += 'Example file'

    def multipart(self):
        """Used in web apps, should never be returned by libmagic"""
        self.log_string += 'Multipart file'

    # ##### Treated as malicious, no reason to have it on a USB key ######
    def message(self):
        """Process a message file."""
        self.log_string += 'Message file'
        self.make_dangerous()

    def model(self):
        """Process a model file."""
        self.log_string += 'Model file'
        self.make_dangerous()

    # ##### Files that will be converted ######
    def text(self):
        """Process an rtf, ooxml, or plaintext file."""
        for mt in Config.mimes_rtf:
            if mt in self.sub_type:
                self.log_string += 'Rich Text file'
                # TODO: need a way to convert it to plain text
                self.force_ext('.txt')
                return
        for mt in Config.mimes_ooxml:
            if mt in self.sub_type:
                self.log_string += 'OOXML File'
                self._ooxml()
                return
        self.log_string += 'Text file'
        self.force_ext('.txt')

    def application(self):
        """Processes an application specific file according to its subtype."""
        for subtype, method in self.app_subtype_methods.items():
            if subtype in self.sub_type:
                method()
                self.log_string += 'Application file'
                return
        self.log_string += 'Unknown Application file'
        self._unknown_app()

    def _executables(self):
        """Processes an executable file."""
        self.add_log_details('processing_type', 'executable')
        self.make_dangerous()

    def _winoffice(self):
        """Processes a winoffice file using olefile/oletools."""
        self.add_log_details('processing_type', 'WinOffice')
        # Try as if it is a valid document
        oid = oletools.oleid.OleID(self.src_path)
        if not olefile.isOleFile(self.src_path):
            # Manual processing, may already count as suspicious
            try:
                ole = olefile.OleFileIO(self.src_path, raise_defects=olefile.DEFECT_INCORRECT)
            except:
                self.add_log_details('not_parsable', True)
                self.make_dangerous()
            if ole.parsing_issues:
                self.add_log_details('parsing_issues', True)
                self.make_dangerous()
            else:
                if ole.exists('macros/vba') or ole.exists('Macros') \
                        or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                    self.add_log_details('macro', True)
                    self.make_dangerous()
        else:
            indicators = oid.check()
            # Encrypted ban be set by multiple checks on the script
            if oid.encrypted.value:
                self.add_log_details('encrypted', True)
                self.make_dangerous()
            if oid.macros.value or oid.ole.exists('macros/vba') or oid.ole.exists('Macros') \
                    or oid.ole.exists('_VBA_PROJECT_CUR') or oid.ole.exists('VBA'):
                self.add_log_details('macro', True)
                self.make_dangerous()
            for i in indicators:
                if i.id == 'ObjectPool' and i.value:
                    # FIXME: Is it suspicious?
                    self.add_log_details('objpool', True)
                elif i.id == 'flash' and i.value:
                    self.add_log_details('flash', True)
                    self.make_dangerous()

    def _ooxml(self):
        """Processes an ooxml file."""
        self.add_log_details('processing_type', 'ooxml')
        try:
            doc = officedissector.doc.Document(self.src_path)
        except Exception:
            # Invalid file
            self.make_dangerous()
            return
        # There are probably other potentially malicious features:
        # fonts, custom props, custom XML
        if doc.is_macro_enabled or len(doc.features.macros) > 0:
            self.add_log_details('macro', True)
            self.make_dangerous()
        if len(doc.features.embedded_controls) > 0:
            self.add_log_details('activex', True)
            self.make_dangerous()
        if len(doc.features.embedded_objects) > 0:
            # Exploited by CVE-2014-4114 (OLE)
            self.add_log_details('embedded_obj', True)
            self.make_dangerous()
        if len(doc.features.embedded_packages) > 0:
            self.add_log_details('embedded_pack', True)
            self.make_dangerous()

    def _libreoffice(self):
        """Processes a libreoffice file."""
        self.add_log_details('processing_type', 'libreoffice')
        # As long as there ar no way to do a sanity check on the files => dangerous
        try:
            lodoc = zipfile.ZipFile(self.src_path, 'r')
        except:
            self.add_log_details('invalid', True)
            self.make_dangerous()
        for f in lodoc.infolist():
            fname = f.filename.lower()
            if fname.startswith('script') or fname.startswith('basic') or \
                    fname.startswith('object') or fname.endswith('.bin'):
                self.add_log_details('macro', True)
                self.make_dangerous()

    def _pdf(self):
        """Processes a PDF file."""
        self.add_log_details('processing_type', 'pdf')
        xmlDoc = PDFiD(self.src_path)
        oPDFiD = cPDFiD(xmlDoc, True)
        # TODO: other keywords?
        if oPDFiD.encrypt.count > 0:
            self.add_log_details('encrypted', True)
            self.make_dangerous()
        if oPDFiD.js.count > 0 or oPDFiD.javascript.count > 0:
            self.add_log_details('javascript', True)
            self.make_dangerous()
        if oPDFiD.aa.count > 0 or oPDFiD.openaction.count > 0:
            self.add_log_details('openaction', True)
            self.make_dangerous()
        if oPDFiD.richmedia.count > 0:
            self.add_log_details('flash', True)
            self.make_dangerous()
        if oPDFiD.launch.count > 0:
            self.add_log_details('launch', True)
            self.make_dangerous()

    def _archive(self):
        """Processes an archive using 7zip. The archive is extracted to a
        temporary directory and self.process_dir is called on that directory.
        The recursive archive depth is increased to protect against archive
        bombs."""
        self.add_log_details('processing_type', 'archive')
        self.is_recursive = True
        # self.log_string += 'Archive extracted, processing content.'

    def _unknown_app(self):
        """Processes an unknown file."""
        self.make_unknown()

    def _binary_app(self):
        """Processses an unknown binary file."""
        self.make_binary()

    #######################
    # Metadata extractors
    def _metadata_exif(self, metadata_file_path):
        img = open(self.src_path, 'rb')
        tags = None

        try:
            tags = exifread.process_file(img, debug=True)
        except Exception as e:
            # TODO: log instead of print
            print("Error while trying to grab full metadata for file {}; retrying for partial data.".format(self.src_path))
            print(e)
        if tags is None:
            try:
                tags = exifread.process_file(img, debug=True)
            except Exception as e:
                # TODO: log instead of print
                print("Failed to get any metadata for file {}.".format(self.src_path))
                print(e)
                img.close()
                return False

        for tag in sorted(tags.keys()):
            # These are long and obnoxious/binary
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail'):
                printable = str(tags[tag])

                # Exifreader truncates data.
                if len(printable) > 25 and printable.endswith(", ... ]"):
                    value = tags[tag].values
                    printable = str(value)

                with open(metadata_file_path, 'w+') as metadata_file:
                    metadata_file.write("Key: {}\tValue: {}\n".format(tag, printable))
        self.add_log_details('metadata', 'exif')
        img.close()
        return True

    def _metadata_png(self, metadata_file_path):
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:
            img = Image.open(self.src_path)
            for tag in sorted(img.info.keys()):
                # These are long and obnoxious/binary
                if tag not in ('icc_profile'):
                    with open(metadata_file_path, 'w+') as metadata_file:
                        metadata_file.write("Key: {}\tValue: {}\n".format(tag, img.info[tag]))
            self.add_log_details('metadata', 'png')
            img.close()
        # Catch decompression bombs
        except Exception as e:
            # TODO: log instead of print
            print("Caught exception processing metadata for {}".format(self.src_path))
            print(e)
            self.make_dangerous()
            return False

    def extract_metadata(self):
        metadata_file_path = self.create_metadata_file(".metadata.txt")
        mt = self.mimetype
        metadata_processing_method = self.metadata_mimetype_methods.get(mt)
        if metadata_processing_method:
            # TODO: should we return metadata and write it here instead of in processing method?
            metadata_processing_method(metadata_file_path)

    #######################
    # ##### Media - audio and video aren't converted ######
    def audio(self):
        """Processes an audio file."""
        self.log_string += 'Audio file'
        self._media_processing()

    def video(self):
        """Processes a video."""
        self.log_string += 'Video file'
        self._media_processing()

    def _media_processing(self):
        """Generic way to process all media files."""
        self.add_log_details('processing_type', 'media')

    def image(self):
        """Processes an image.

        Extracts metadata to dest key if metadata is present. Creates a
        temporary directory on dest key, opens the using PIL.Image,saves it to
        the temporary directory, and copies it to the destination."""
        # TODO: make sure this method works for png, gif, tiff
        if self.has_metadata():
            self.extract_metadata()
        tempdir_path = self._make_tempdir()
        tempfile_path = os.path.join(tempdir_path, self.filename)
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:  # Do image conversions
            img_in = Image.open(self.src_path)
            img_out = Image.frombytes(img_in.mode, img_in.size, img_in.tobytes())
            img_out.save(tempfile_path)
            self.src_path = tempfile_path
        except Exception as e:  # Catch decompression bombs
            # TODO: change this from printing to logging
            print("Caught exception (possible decompression bomb?) while translating file {}.".format(self.src_path))
            print(e)
            self.make_dangerous()
        self.log_string += 'Image file'
        self.add_log_details('processing_type', 'image')


class KittenGroomerFileCheck(KittenGroomerBase):

    def __init__(self, root_src, root_dst, max_recursive_depth=2, debug=False):
        super(KittenGroomerFileCheck, self).__init__(root_src, root_dst, debug)
        self.recursive_archive_depth = 0
        self.max_recursive_depth = max_recursive_depth

    def process_dir(self, src_dir, dst_dir):
        """Main function coordinating file processing."""
        # TODO: Think we want to move write_log elsewhere:
        # if self.recursive_archive_depth > 0:
        #     self.write_log()
        # TODO: Can we clean up the way we handle relative_path?
        for srcpath in self.list_all_files(src_dir):
            dstpath = srcpath.replace(src_dir, dst_dir)
            relative_path = srcpath.replace(src_dir + '/', '')
            self.cur_file = File(srcpath, dstpath, self.logger)
            # TODO: move this logging code elsewhere
            self.logger.log.info('Processing {} ({}/{})',
                                 relative_path,
                                 self.cur_file.main_type,
                                 self.cur_file.sub_type)
            self.process_file(self.cur_file)

    def process_file(self, file):
        file.check()
        if file.is_recursive:
            self.process_archive(file)
        else:
            # TODO: Check if should be copied, make an attribute for should be copied True/False
            self._safe_copy()
        file.write_log()
        if hasattr(file, "tempdir_path"):
            self._safe_rmtree(file.tempdir_path)

    def process_archive(self, file):
        """Unpacks an archive using 7zip and processes contents.

        Should be given a Kittengroomer file object whose src_path points
        to an archive."""
        self.recursive_archive_depth += 1
        # Check for archivebomb
        if self.recursive_archive_depth >= self.max_recursive_depth:
            self._handle_archivebomb(file)
        else:
            tempdir_path = file._make_tempdir()
            # Unpack the archive
            base_command = '{} -p1 x "{}" -o"{}" -bd -aoa'
            extract_command = base_command.format(SEVENZ_PATH, file.src_path, tempdir_path)
            file._run_process(extract_command)
            # Add it to the tree
            self.logger.tree(tempdir_path)
            # List all files, process them
            self.process_dir(tempdir_path, file.dst_path)
            # Clean up
            self._safe_rmtree(tempdir_path)
        self.recursive_archive_depth -= 1


    def _handle_archivebomb(self, file):
        file.make_dangerous()
        file.add_log_details('Archive Bomb', True)
        self.logger.log.warning('ARCHIVE BOMB.')
        self.logger.log.warning('The content of the archive contains recursively other archives.')
        self.logger.log.warning('This is a bad sign so the archive is not extracted to the destination key.')
        # TODO: are we sure we want to delete the archive on the source key? Commenting out for now
        # self._safe_rmtree(file.src_dir)
        # What is the goal of this code:
        # if file.src_dir.endswith('_temp'):
        #     # TODO: change the way bomb_path is constructed and the way we check for tempdir
        #     bomb_path = file.src_dir[:-len('_temp')]
        #     self._safe_remove(bomb_path)

    def run(self):
        self.process_dir(self.src_root_dir, self.dst_root_dir)


def main(kg_implementation, description):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.run()


if __name__ == '__main__':
    main(KittenGroomerFileCheck, 'File sanitizer used in CIRCLean. Renames potentially dangerous files.')
