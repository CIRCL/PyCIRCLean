#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import mimetypes
import shlex
import subprocess
import zipfile
import argparse
import shutil

import oletools.oleid
import olefile
import officedissector
import warnings
import exifread
from PIL import Image
from pdfid import PDFiD, cPDFiD

from kittengroomer import FileBase, KittenGroomerBase, Logging
from bin.config import Config


SEVENZ_PATH = '/usr/bin/7z'


class File(FileBase):
    """
    Main file object

    Created for each file that is processed by KittenGroomer. Contains all
    filetype-specific processing methods.
    """

    def __init__(self, src_path, dst_path, logger=None):
        super(File, self).__init__(src_path, dst_path)
        self.is_archive = False
        self.logger = logger
        self.tempdir_path = self.dst_path + '_temp'

        subtypes_apps = (
            (Config.mimes_office, self._winoffice),
            (Config.mimes_ooxml, self._ooxml),
            (Config.mimes_rtf, self.text),
            (Config.mimes_libreoffice, self._libreoffice),
            (Config.mimes_pdf, self._pdf),
            (Config.mimes_xml, self.text),
            (Config.mimes_ms, self._executables),
            (Config.mimes_compressed, self._archive),
            (Config.mimes_data, self._binary_app),
        )
        self.app_subtype_methods = self._make_method_dict(subtypes_apps)

        types_metadata = (
            (Config.mimes_exif, self._metadata_exif),
            (Config.mimes_png, self._metadata_png),
        )
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

    def __repr__(self):
        return "<filecheck.File object: {{{}}}>".format(self.filename)

    def _check_extension(self):
        """
        Guess the file's mimetype based on its extension.

        If the file's mimetype (as determined by libmagic) is contained in
        the `mimetype` module's list of valid mimetypes and the expected
        mimetype based on its extension differs from the mimetype determined
        by libmagic, then mark the file as dangerous.
        """
        if not self.has_extension:
            self.make_dangerous('File has no extension')
        else:
            if self.extension in Config.override_ext:
                expected_mimetype = Config.override_ext[self.extension]
            else:
                expected_mimetype, encoding = mimetypes.guess_type(self.src_path,
                                                                   strict=False)
                if expected_mimetype in Config.aliases:
                    expected_mimetype = Config.aliases[expected_mimetype]
            is_known_extension = self.extension in mimetypes.types_map.keys()
            if is_known_extension and expected_mimetype != self.mimetype:
                self.make_dangerous('Mimetype does not match expected mimetype for this extension')

    def _check_mimetype(self):
        """
        Compare mimetype (as determined by libmagic) to extension.

        Determine whether the extension that are normally associated with
        the mimetype include the file's actual extension.
        """
        if not self.has_mimetype:
            self.make_dangerous('File has no mimetype')
        else:
            if self.mimetype in Config.aliases:
                mimetype = Config.aliases[self.mimetype]
            else:
                mimetype = self.mimetype
            expected_extensions = mimetypes.guess_all_extensions(mimetype,
                                                                 strict=False)
            if expected_extensions:
                if self.has_extension and self.extension not in expected_extensions:
                    self.make_dangerous('Extension does not match expected extensions for this mimetype')

    def _check_filename(self):
        """
        Verify the filename

        If the filename contains any dangerous or specific characters, handle
        them appropriately.
        """
        if self.filename.startswith('.'):
            macos_hidden_files = set(
                '.Trashes', '._.Trashes', '.DS_Store', '.fseventsd', '.Spotlight-V100'
            )
            if self.filename in macos_hidden_files:
                self.add_description('MacOS metadata file, added by MacOS to certain USB drives and directories')
                self.should_copy = False
        right_to_left_override = u"\u202E"
        if right_to_left_override in self.filename:
            self.make_dangerous('Filename contains dangerous character')
            new_filename = self.filename.replace(right_to_left_override, '')
            self.set_property('filename', new_filename)

    def _check_malicious_exts(self):
        """Check that the file's extension isn't contained in a blacklist"""
        if self.extension in Config.malicious_exts:
            self.make_dangerous('Extension identifies file as potentially dangerous')

    def check(self):
        """
        Main file processing method.

        First, checks for basic properties that might indicate a dangerous file.
        If the file isn't dangerous, then delegates to various helper methods
        for filetype-specific checks based on the file's mimetype.
        """
        # Any of these methods can call make_dangerous():
        self._check_malicious_exts()
        self._check_mimetype()
        self._check_extension()
        self._check_filename()  # can mutate self.filename

        if not self.is_dangerous:
            self.mime_processing_options.get(self.maintype, self.unknown)()

    def write_log(self):
        """Pass information about the file to self.logger."""
        if self.logger:
            props = self.get_all_props()
            if not self.is_archive:
                if os.path.exists(self.tempdir_path):
                    # FIXME: in_tempdir is a hack to make image files appear at the correct tree depth in log
                    self.logger.add_file(self.src_path, props, in_tempdir=True)
                    return
            self.logger.add_file(self.src_path, props)
        else:
            raise Warning("No logger associated with this File")

    # ##### Helper functions #####
    def _make_method_dict(self, list_of_tuples):
        """Returns a dictionary with mimetype: method pairs."""
        dict_to_return = {}
        for list_of_subtypes, method in list_of_tuples:
            for subtype in list_of_subtypes:
                dict_to_return[subtype] = method
        return dict_to_return

    @property
    def has_metadata(self):
        """True if filetype typically contains metadata, else False."""
        if self.mimetype in Config.mimes_metadata:
            return True
        return False

    def make_tempdir(self):
        """Make a temporary directory at self.tempdir_path."""
        if not os.path.exists(self.tempdir_path):
            os.makedirs(self.tempdir_path)
        return self.tempdir_path

    #######################
    # ##### Discarded mimetypes, reason in the docstring ######
    def inode(self):
        """Empty file or symlink."""
        if self.is_symlink:
            symlink_path = self.get_property('symlink')
            self.add_description('File is a symlink to {}'.format(symlink_path))
        else:
            self.add_description('File is an inode (empty file)')
        self.should_copy = False

    def unknown(self):
        """Main type should never be unknown."""
        self.add_description('Unknown mimetype')
        self.should_copy = False

    def example(self):
        """Used in examples, should never be returned by libmagic."""
        self.add_description('Example file')
        self.should_copy = False

    def multipart(self):
        """Used in web apps, should never be returned by libmagic"""
        self.add_description('Multipart file - usually found in web apps')
        self.should_copy = False

    # ##### Treated as malicious, no reason to have it on a USB key ######
    def message(self):
        """Process a message file."""
        self.make_dangerous('Message file - should not be found on USB key')

    def model(self):
        """Process a model file."""
        self.make_dangerous('Model file - should not be found on USB key')

    # ##### Files that will be converted ######
    def text(self):
        """Process an rtf, ooxml, or plaintext file."""
        for mt in Config.mimes_rtf:
            if mt in self.subtype:
                self.add_description('Rich Text (rtf) file')
                # TODO: need a way to convert it to plain text
                self.force_ext('.txt')
                return
        for mt in Config.mimes_ooxml:
            if mt in self.subtype:
                self.add_description('OOXML (openoffice) file')
                self._ooxml()
                return
        self.add_description('Plain text file')
        self.force_ext('.txt')

    def application(self):
        """Process an application specific file according to its subtype."""
        if self.subtype in self.app_subtype_methods:
            method = self.app_subtype_methods[self.subtype]
            method()
        else:
            self._unknown_app()

    def _executables(self):
        """Process an executable file."""
        # LOG: change the processing_type property to some other name or include in file_string
        self.make_dangerous('Executable file')

    def _winoffice(self):
        """Process a winoffice file using olefile/oletools."""
        oid = oletools.oleid.OleID(self.src_path)  # First assume a valid file
        if not olefile.isOleFile(self.src_path):
            # Manual processing, may already count as suspicious
            try:
                ole = olefile.OleFileIO(self.src_path, raise_defects=olefile.DEFECT_INCORRECT)
            except:
                self.make_dangerous('Unparsable WinOffice file')
            if ole.parsing_issues:
                self.make_dangerous('Parsing issues with WinOffice file')
            else:
                if ole.exists('macros/vba') or ole.exists('Macros') \
                        or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                    self.make_dangerous('WinOffice file containing a macro')
        else:
            indicators = oid.check()
            # Encrypted can be set by multiple checks on the script
            if oid.encrypted.value:
                self.make_dangerous('Encrypted WinOffice file')
            if oid.macros.value or oid.ole.exists('macros/vba') or oid.ole.exists('Macros') \
                    or oid.ole.exists('_VBA_PROJECT_CUR') or oid.ole.exists('VBA'):
                self.make_dangerous('WinOffice file containing a macro')
            for i in indicators:
                if i.id == 'ObjectPool' and i.value:
                    self.make_dangerous('WinOffice file containing an object pool')
                elif i.id == 'flash' and i.value:
                    self.make_dangerous('WinOffice file with embedded flash')
        self.add_description('WinOffice file')

    def _ooxml(self):
        """Process an ooxml file."""
        try:
            doc = officedissector.doc.Document(self.src_path)
        except Exception:
            self.make_dangerous('Invalid ooxml file')
            return
        # There are probably other potentially malicious features:
        # fonts, custom props, custom XML
        if doc.is_macro_enabled or len(doc.features.macros) > 0:
            self.make_dangerous('Ooxml file containing macro')
        if len(doc.features.embedded_controls) > 0:
            self.make_dangerous('Ooxml file with activex')
        if len(doc.features.embedded_objects) > 0:
            # Exploited by CVE-2014-4114 (OLE)
            self.make_dangerous('Ooxml file with embedded objects')
        if len(doc.features.embedded_packages) > 0:
            self.make_dangerous('Ooxml file with embedded packages')
        if not self.is_dangerous:
            self.add_description('Ooxml file')

    def _libreoffice(self):
        """Process a libreoffice file."""
        # As long as there is no way to do a sanity check on the files => dangerous
        try:
            lodoc = zipfile.ZipFile(self.src_path, 'r')
        except:
            # TODO: are there specific exceptions we should catch here? Or should it be everything
            self.make_dangerous('Invalid libreoffice file')
        for f in lodoc.infolist():
            fname = f.filename.lower()
            if fname.startswith('script') or fname.startswith('basic') or \
                    fname.startswith('object') or fname.endswith('.bin'):
                self.make_dangerous('Libreoffice file containing executable code')
        if not self.is_dangerous:
            self.add_description('Libreoffice file')

    def _pdf(self):
        """Process a PDF file."""
        xmlDoc = PDFiD(self.src_path)
        oPDFiD = cPDFiD(xmlDoc, True)
        # TODO: are there other pdf characteristics which should be dangerous?
        if oPDFiD.encrypt.count > 0:
            self.make_dangerous('Encrypted pdf')
        if oPDFiD.js.count > 0 or oPDFiD.javascript.count > 0:
            self.make_dangerous('Pdf with embedded javascript')
        if oPDFiD.aa.count > 0 or oPDFiD.openaction.count > 0:
            self.make_dangerous('Pdf with openaction(s)')
        if oPDFiD.richmedia.count > 0:
            self.make_dangerous('Pdf containing flash')
        if oPDFiD.launch.count > 0:
            self.make_dangerous('Pdf with launch action(s)')
        if oPDFiD.xfa.count > 0:
            self.make_dangerous('Pdf with XFA structures')
        if oPDFiD.objstm.count > 0:
            self.make_dangerous('Pdf with ObjectStream structures')
        if not self.is_dangerous:
            self.add_description('Pdf file')

    def _archive(self):
        """
        Process an archive using 7zip.

        The archive is extracted to a temporary directory and self.process_dir
        is called on that directory. The recursive archive depth is increased
        to protect against archive bombs.
        """
        # TODO: change this to something archive type specific instead of generic 'Archive'
        self.add_description('Archive')
        self.should_copy = False
        self.is_archive = True

    def _unknown_app(self):
        """Process an unknown file."""
        self.make_dangerous('Unknown application file')

    def _binary_app(self):
        """Process an unknown binary file."""
        self.make_dangerous('Unknown binary file')

    #######################
    # Metadata extractors
    def _metadata_exif(self, metadata_file_path):
        """Read exif metadata from a jpg or tiff file using exifread."""
        # TODO: can we shorten this method somehow?
        img = open(self.src_path, 'rb')
        tags = None
        try:
            tags = exifread.process_file(img, debug=True)
        except Exception as e:
            self.add_error(e, "Error while trying to grab full metadata for file {}; retrying for partial data.".format(self.src_path))
        if tags is None:
            try:
                tags = exifread.process_file(img, debug=True)
            except Exception as e:
                self.add_error(e, "Failed to get any metadata for file {}.".format(self.src_path))
                img.close()
                return False
        for tag in sorted(tags.keys()):
            # These tags are long and obnoxious/binary so we don't add them
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail'):
                tag_string = str(tags[tag])
                # Exifreader truncates data.
                if len(tag_string) > 25 and tag_string.endswith(", ... ]"):
                    tag_value = tags[tag].values
                    tag_string = str(tag_value)
                with open(metadata_file_path, 'w+') as metadata_file:
                    metadata_file.write("Key: {}\tValue: {}\n".format(tag, tag_string))
        # TODO: how do we want to log metadata?
        self.set_property('metadata', 'exif')
        img.close()
        return True

    def _metadata_png(self, metadata_file_path):
        """Extract metadata from a png file using PIL/Pillow."""
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:
            img = Image.open(self.src_path)
            for tag in sorted(img.info.keys()):
                # These are long and obnoxious/binary
                if tag not in ('icc_profile'):
                    with open(metadata_file_path, 'w+') as metadata_file:
                        metadata_file.write("Key: {}\tValue: {}\n".format(tag, img.info[tag]))
            # LOG: handle metadata
            self.set_property('metadata', 'png')
            img.close()
        except Exception as e:  # Catch decompression bombs
            # TODO: only catch DecompressionBombWarnings here?
            self.add_error(e, "Caught exception processing metadata for {}".format(self.src_path))
            self.make_dangerous('exception processing metadata')
            return False

    def extract_metadata(self):
        """Create metadata file and call correct metadata extraction method."""
        metadata_file_path = self.create_metadata_file(".metadata.txt")
        mt = self.mimetype
        metadata_processing_method = self.metadata_mimetype_methods.get(mt)
        if metadata_processing_method:
            # TODO: should we return metadata and write it here instead of in processing method?
            metadata_processing_method(metadata_file_path)

    #######################
    # ##### Media - audio and video aren't converted ######
    def audio(self):
        """Process an audio file."""
        self.add_description('Audio file')
        self._media_processing()

    def video(self):
        """Process a video."""
        self.add_description('Video file')
        self._media_processing()

    def _media_processing(self):
        """Generic way to process all media files."""
        self.add_description('Media file')

    def image(self):
        """
        Process an image.

        Extracts metadata to dest key using self.extract_metada() if metadata
        is present. Creates a temporary directory on dest key, opens the image
        using PIL.Image, saves it to the temporary directory, and copies it to
        the destination.
        """
        # TODO: make sure this method works for png, gif, tiff
        if self.has_metadata:
            self.extract_metadata()
        tempdir_path = self.make_tempdir()
        tempfile_path = os.path.join(tempdir_path, self.filename)
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:  # Do image conversions
            img_in = Image.open(self.src_path)
            img_out = Image.frombytes(img_in.mode, img_in.size, img_in.tobytes())
            img_out.save(tempfile_path)
            self.src_path = tempfile_path
        except Exception as e:  # Catch decompression bombs
            # TODO: change this from all Exceptions to specific DecompressionBombWarning
            self.add_error(e, "Caught exception (possible decompression bomb?) while translating file {}.".format(self.src_path))
            self.make_dangerous('Image file containing decompression bomb')
        if not self.is_dangerous:
            self.add_description('Image file')


class GroomerLogger(object):
    """Groomer logging interface."""

    def __init__(self, src_root_path, dst_root_path, debug=False):
        self._src_root_path = src_root_path
        self._dst_root_path = dst_root_path
        self._log_dir_path = self._make_log_dir(dst_root_path)
        self.log_path = os.path.join(self._log_dir_path, 'circlean_log.txt')
        self._add_root_dir(src_root_path)
        if debug:
            self.log_debug_err = os.path.join(self._log_dir_path, 'debug_stderr.log')
            self.log_debug_out = os.path.join(self._log_dir_path, 'debug_stdout.log')
        else:
            self.log_debug_err = os.devnull
            self.log_debug_out = os.devnull

    def _make_log_dir(self, root_dir_path):
        """Create the directory in the dest dir that will hold the logs"""
        log_dir_path = os.path.join(root_dir_path, 'logs')
        if os.path.exists(log_dir_path):
            shutil.rmtree(log_dir_path)
        os.makedirs(log_dir_path)
        return log_dir_path

    def _add_root_dir(self, root_path):
        """Add the root directory to the log"""
        dirname = os.path.split(root_path)[1] + '/'
        with open(self.log_path, mode='ab') as lf:
            lf.write(bytes(dirname, 'utf-8'))
            lf.write(b'\n')

    def add_file(self, file_path, file_props, in_tempdir=False):
        """Add a file to the log. Takes a path and a dict of file properties."""
        depth = self._get_path_depth(file_path)
        try:
            file_hash = Logging.computehash(file_path)[:6]
        except IsADirectoryError:
            file_hash = 'directory'
        if file_props['is_symlink']:
            symlink_template = "+- NOT COPIED: symbolic link to {name} ({sha_hash})"
            log_string = symlink_template.format(
                name=file_props['symlink_path'],
                sha_hash=file_hash
            )
        else:
            if file_props['is_dangerous']:
                category = "Dangerous"
            else:
                category = "Normal"
            size_string = self._format_file_size(file_props['file_size'])
            if not file_props['copied']:
                copied_string = 'NOT COPIED: '
            else:
                copied_string = ''
            file_template = "+- {copied}{name} ({sha_hash}): {size}, type: {mt}/{st}. {cat}: {desc_str}"
            log_string = file_template.format(
                copied=copied_string,
                name=file_props['filename'],
                sha_hash=file_hash,
                size=size_string,
                mt=file_props['maintype'],
                st=file_props['subtype'],
                cat=category,
                desc_str=file_props['description_string'],
            )
        if file_props['errors']:
            error_string = ', '.join([str(key) for key in file_props['errors']])
            log_string.append(' Errors: ' + error_string)
        if in_tempdir:
            depth -= 1
        self._write_line_to_log(log_string, depth)

    def add_dir(self, dir_path):
        """Add a directory to the log"""
        path_depth = self._get_path_depth(dir_path)
        dirname = os.path.split(dir_path)[1] + '/'
        log_line = '+- ' + dirname
        self._write_line_to_log(log_line, path_depth)

    def _format_file_size(self, size):
        """Returns a string with the file size and appropriate unit"""
        file_size = size
        for unit in ('B', 'KB', 'MB', 'GB'):
            if file_size < 1024:
                return str(int(file_size)) + unit
            else:
                file_size = file_size / 1024
        return str(int(file_size)) + 'GB'

    def _get_path_depth(self, path):
        """Returns the relative path depth compared to root directory"""
        if self._dst_root_path in path:
            base_path = self._dst_root_path
        elif self._src_root_path in path:
            base_path = self._src_root_path
        relpath = os.path.relpath(path, base_path)
        path_depth = relpath.count(os.path.sep)
        return path_depth

    def _write_line_to_log(self, line, indentation_depth):
        """
        Write a line to the log

        Pad the line according to the `indentation_depth`.
        """
        padding = b'   '
        padding += b'|  ' * indentation_depth
        line_bytes = os.fsencode(line)
        with open(self.log_path, mode='ab') as lf:
            lf.write(padding)
            lf.write(line_bytes)
            lf.write(b'\n')


class KittenGroomerFileCheck(KittenGroomerBase):

    def __init__(self, root_src, root_dst, max_recursive_depth=2, debug=False):
        super(KittenGroomerFileCheck, self).__init__(root_src, root_dst)
        self.recursive_archive_depth = 0
        self.max_recursive_depth = max_recursive_depth
        self.logger = GroomerLogger(root_src, root_dst, debug)

    def __repr__(self):
        return "filecheck.KittenGroomerFileCheck object: {{{}}}".format(
            os.path.basename(self.src_root_path)
        )

    def process_dir(self, src_dir, dst_dir):
        """Process a directory on the source key."""
        for srcpath in self.list_files_dirs(src_dir):
            if not os.path.islink(srcpath) and os.path.isdir(srcpath):
                self.logger.add_dir(srcpath)
            else:
                dstpath = os.path.join(dst_dir, os.path.basename(srcpath))
                cur_file = File(srcpath, dstpath, self.logger)
                self.process_file(cur_file)

    def process_file(self, file):
        """
        Process an individual file.

        Check the file, handle archives using self.process_archive, copy
        the file to the destionation key, and clean up temporary directory.
        """
        file.check()
        if file.is_archive:
            self.process_archive(file)
        else:
            if file.should_copy:
                file.safe_copy()
                file.set_property('copied', True)
            file.write_log()
        # TODO: Can probably handle cleaning up the tempdir better
        if hasattr(file, 'tempdir_path'):
            self.safe_rmtree(file.tempdir_path)

    def process_archive(self, file):
        """
        Unpack an archive using 7zip and process contents using process_dir.

        Should be given a Kittengroomer file object whose src_path points
        to an archive.
        """
        self.recursive_archive_depth += 1
        if self.recursive_archive_depth >= self.max_recursive_depth:
            file.make_dangerous('Archive bomb')
        else:
            tempdir_path = file.make_tempdir()
            command_str = '{} -p1 x "{}" -o"{}" -bd -aoa'
            unpack_command = command_str.format(SEVENZ_PATH,
                                                file.src_path, tempdir_path)
            self._run_process(unpack_command)
            file.write_log()
            self.process_dir(tempdir_path, file.dst_path)
            self.safe_rmtree(tempdir_path)
        self.recursive_archive_depth -= 1

    def _run_process(self, command_string, timeout=None):
        """Run command_string in a subprocess, wait until it finishes."""
        args = shlex.split(command_string)
        with open(self.logger.log_debug_err, 'ab') as stderr, open(self.logger.log_debug_out, 'ab') as stdout:
            try:
                subprocess.check_call(args, stdout=stdout, stderr=stderr, timeout=timeout)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                return
        return True

    def list_files_dirs(self, root_dir_path):
        """
        Returns a list of all files and directories

        Performs a depth-first traversal of the file tree.
        """
        queue = []
        for path in sorted(os.listdir(root_dir_path), key=lambda x: str.lower(x)):
            full_path = os.path.join(root_dir_path, path)
            # check for symlinks first to prevent getting trapped in infinite symlink recursion
            if os.path.islink(full_path):
                queue.append(full_path)
            elif os.path.isdir(full_path):
                queue.append(full_path)
                queue += self.list_files_dirs(full_path)
            elif os.path.isfile(full_path):
                queue.append(full_path)
        return queue

    def run(self):
        self.process_dir(self.src_root_path, self.dst_root_path)


def main(kg_implementation, description):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.run()


if __name__ == '__main__':
    main(KittenGroomerFileCheck, 'File sanitizer used in CIRCLean. Renames potentially dangerous files.')
