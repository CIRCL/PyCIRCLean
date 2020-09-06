#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import mimetypes
import shlex
import subprocess
import zipfile
import argparse
import random
import shutil
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Callable, Optional

import oletools.oleid  # type: ignore
import olefile  # type: ignore
import officedissector  # type: ignore
import warnings
import exifread  # type: ignore
from PIL import Image  # type: ignore
from pdfid import PDFiD, cPDFiD  # type: ignore

from kittengroomer import FileBase, KittenGroomerBase, Logging


class Config:
    """Configuration information for filecheck.py."""
    # MIMES
    # Application subtypes (mimetype: 'application/<subtype>')
    mimes_ooxml: Tuple[str, ...] = ('vnd.openxmlformats-officedocument.',)
    mimes_office: Tuple[str, ...] = ('msword', 'vnd.ms-',)
    mimes_libreoffice: Tuple[str, ...] = ('vnd.oasis.opendocument',)
    mimes_rtf: Tuple[str, ...] = ('rtf', 'richtext',)
    mimes_pdf: Tuple[str, ...] = ('pdf', 'postscript',)
    mimes_xml: Tuple[str, ...] = ('xml',)
    mimes_csv: Tuple[str, ...] = ('csv','text/csv')
    mimes_ms: Tuple[str, ...] = ('dosexec',)
    mimes_compressed: Tuple[str, ...] = ('zip', 'rar', 'x-rar', 'bzip2', 'lzip', 'lzma', 'lzop',
                                         'xz', 'compress', 'gzip', 'tar',)
    mimes_data: Tuple[str, ...] = ('octet-stream',)
    mimes_audio: Tuple[str, ...] = ('ogg',)

    # Image subtypes
    mimes_exif: Tuple[str, ...] = ('image/jpeg', 'image/tiff',)
    mimes_png: Tuple[str, ...] = ('image/png',)

    # Mimetypes with metadata
    mimes_metadata: Tuple[str, ...] = ('image/jpeg', 'image/tiff', 'image/png',)

    # Mimetype aliases
    aliases: Dict[str, str] = {
        # Win executables
        'application/x-msdos-program': 'application/x-dosexec',
        'application/x-dosexec': 'application/x-msdos-program',
        # Other apps with confusing mimetypes
        'application/rtf': 'text/rtf',
        'application/rar': 'application/x-rar',
        'application/ogg': 'audio/ogg',
        'audio/ogg': 'application/ogg'
    }

    # Mime Type / Extension fix. TODO: Doesn't quite work....????
    mimetypes.add_type('text/plain','.csv',False)
    mimetypes.add_type('text/csv','.csv',False)
    mimetypes.add_type('application/vnd.apple.numbers', '.numbers', True)
    mimetypes.add_type('application/vnd.apple.pages', '.pages', False)
    mimetypes.add_type('application/vnd.apple.keynote', '.keynote', False)

    # EXTS
    # Commonly used malicious extensions
    # Sources: http://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows/
    # https://github.com/wiregit/wirecode/blob/master/components/core-settings/src/main/java/org/limewire/core/settings/FilterSettings.java
    malicious_exts: Tuple[str, ...] = (
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
        # Google chrome malicious extensions
        ".ad", ".ade", ".adp", ".ah", ".apk", ".app", ".application", ".asp",
        ".asx", ".bas", ".bash", ".bat", ".cfg", ".chi", ".chm", ".class",
        ".cmd", ".com", ".command", ".crt", ".crx", ".csh", ".deb", ".dex",
        ".dll", ".drv", ".exe", ".fxp", ".grp", ".hlp", ".hta", ".htm", ".html",
        ".htt", ".inf", ".ini", ".ins", ".isp", ".jar", ".jnlp", ".user.js",
        ".js", ".jse", ".ksh", ".lnk", ".local", ".mad", ".maf", ".mag", ".mam",
        ".manifest", ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw",
        ".mda", ".mdb", ".mde", ".mdt", ".mdw", ".mdz", ".mht", ".mhtml", ".mmc",
        ".mof", ".msc", ".msh", ".mshxml", ".msi", ".msp", ".mst", ".ocx", ".ops",
        ".pcd", ".pif", ".pkg", ".pl", ".plg", ".prf", ".prg", ".pst", ".py",
        ".pyc", ".pyw", ".rb", ".reg", ".rpm", ".scf", ".scr", ".sct", ".sh",
        ".shar", ".shb", ".shs", ".shtm", ".shtml", ".spl", ".svg", ".swf", ".sys",
        ".tcsh", ".url", ".vb", ".vbe", ".vbs", ".vsd", ".vsmacros", ".vss",
        ".vst", ".vsw", ".ws", ".wsc", ".wsf", ".wsh", ".xbap", ".xht", ".xhtm",
        ".xhtml", ".xml", ".xsl", ".xslt", ".website", ".msh1", ".msh2", ".msh1xml",
        ".msh2xml", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".xnk",
        ".appref-ms", ".gadget", ".efi", ".fon", ".partial", ".svg", ".xml",
        ".xrm_ms", ".xsl", ".action", ".bin", ".inx", ".ipa", ".isu", ".job",
        ".out", ".pad", ".paf", ".rgs", ".u3p", ".vbscript", ".workflow", ".001",
        ".ace", ".arc", ".arj", ".b64", ".balz", ".bhx", ".cab", ".cpio", ".fat",
        ".hfs", ".hqx", ".iso", ".lha", ".lpaq1", ".lpaq5", ".lpaq8", ".lzh",
        ".mim", ".ntfs", ".paq8f", ".paq8jd", ".paq8l", ".paq8o", ".pea", ".quad",
        ".r00", ".r01", ".r02", ".r03", ".r04", ".r05", ".r06", ".r07", ".r08",
        ".r09", ".r10", ".r11", ".r12", ".r13", ".r14", ".r15", ".r16", ".r17",
        ".r18", ".r19", ".r20", ".r21", ".r22", ".r23", ".r24", ".r25", ".r26",
        ".r27", ".r28", ".r29", ".squashfs", ".swm", ".tpz", ".txz", ".tz", ".udf",
        ".uu", ".uue", ".vhd", ".vmdk", ".wim", ".wrc", ".xar", ".xxe", ".z",
        ".zipx", ".zpaq", ".cdr", ".dart", ".dc42", ".diskcopy42", ".dmg",
        ".dmgpart", ".dvdr", ".img", ".imgpart", ".ndif", ".smi", ".sparsebundle",
        ".sparseimage", ".toast", ".udif",
    )

    # Sometimes, mimetypes.guess_type gives unexpected results, such as for .tar.gz files:
    # In [12]: mimetypes.guess_type('toot.tar.gz', strict=False)
    # Out[12]: ('application/x-tar', 'gzip')
    # It works as expected if you do mimetypes.guess_type('application/gzip', strict=False)
    override_ext: Dict[str, str] = {'.gz':       'application/gzip'
                                   , '.csv':     'text/csv' #,'text/plain' ) 
                                   , '.numbers': 'application/vnd.apple.numbers' #,'application/zip')
                                   , '.pages':   'application/vnd.apple.pages' #,'application/zip')  
                                   , '.keynote': 'application/vnd.apple.keynote' #,'application/zip') 
                                   }


SEVENZ_PATH = '/usr/bin/7z'


class File(FileBase):
    """
    Main file object

    Created for each file that is processed by KittenGroomer. Contains all
    filetype-specific processing methods.
    """

    def __init__(self, src_path: Path, dst_path: Path):
        super(File, self).__init__(src_path, dst_path)
        self.is_archive: bool = False
        self.tempdir_path: Path = Path(str(self.dst_path) + '_temp')

        subtypes_apps: Tuple[Tuple[Tuple[str, ...], Callable], ...] = (
            (Config.mimes_office, self._winoffice),
            (Config.mimes_ooxml, self._ooxml),
            (Config.mimes_rtf, self.text),
            (Config.mimes_libreoffice, self._libreoffice),
            (Config.mimes_pdf, self._pdf),
            (Config.mimes_xml, self.text),
            (Config.mimes_csv, self.text),
            (Config.mimes_ms, self._executables),
            (Config.mimes_compressed, self._archive),
            (Config.mimes_data, self._binary_app),
            (Config.mimes_audio, self.audio)
        )
        self.app_subtype_methods: Dict[str, Callable] = self._make_method_dict(subtypes_apps)

        types_metadata: Tuple[Tuple[Tuple[str, ...], Callable], ...] = (
            (Config.mimes_exif, self._metadata_exif),
            (Config.mimes_png, self._metadata_png),
        )
        self.metadata_mimetype_methods: Dict[str, Callable] = self._make_method_dict(types_metadata)

        self.mime_processing_options: Dict[str, Callable] = {
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
                expected_mimetypes = Config.override_ext[self.extension]
                encoding = None
                self.mimetype = expected_mimetypes
            else:
                expected_mimetype, encoding = mimetypes.guess_type(str(self.src_path),
                                                                   strict=False)

                expected_mimetypes = [expected_mimetype]
                if expected_mimetype in Config.aliases:
                    expected_mimetypes.append(Config.aliases[expected_mimetype])
            if (encoding is None) and (os.path.getsize(self.src_path) == 0):
                is_empty_file = True
            else:
                is_empty_file = False

            is_known_extension = self.extension in mimetypes.types_map.keys()
            if is_known_extension and self.mimetype not in expected_mimetypes and not is_empty_file:
                self.make_dangerous(f'Mimetype does not match expected mimetypes ({expected_mimetypes}) for this extension')

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
            if mimetype in Config.aliases:
                expected_extensions += mimetypes.guess_all_extensions(Config.aliases[mimetype], strict=False)
            if expected_extensions:
                if self.has_extension and self.extension not in expected_extensions:
                    self.make_dangerous(f'Extension does not match expected extensions ({expected_extensions}) for this mimetype')

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
                self.add_description('MacOS metadata file, added by MacOS to USB drives and some directories')
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

    def _compute_random_hashes(self):
        """Compute a random amount of hashes at random positions in the file to ensure integrity after the copy (mitigate TOCTOU attacks)"""
        if not os.path.exists(self.src_path) or os.path.isdir(self.src_path) or self.maintype == 'image':
            # Images are converted, no need to compute the hashes
            return
        self.random_hashes = []
        if self.size < 64:
            # hash the whole file
            self.block_length = self.size
        else:
            if self.size < 128:
                # Get a random length between 16 and the size of the file
                self.block_length = random.randint(16, self.size)
            else:
                # Get a random length between 16 and 128
                self.block_length = random.randint(16, 128)

        for i in range(random.randint(3, 6)):  # Do a random amound of read on the file (between 5 and 10)
            start_pos = random.randint(0, self.size - self.block_length)  # Pick a random length for the hash to compute
            with open(self.src_path, 'rb') as f:
                f.seek(start_pos)
                hashed = hashlib.sha256(f.read(self.block_length)).hexdigest()
                self.random_hashes.append((start_pos, hashed))
                time.sleep(random.uniform(0.1, 0.5))  # Add a random sleep length

    def _validate_random_hashes(self) -> bool:
        """Validate hashes computed by _compute_random_hashes"""
        if not os.path.exists(self.src_path) or os.path.isdir(self.src_path) or self.maintype == 'image':
            # Images are converted, we don't have to fear TOCTOU
            return True
        for start_pos, hashed_src in self.random_hashes:
            with open(self.dst_path, 'rb') as f:
                f.seek(start_pos)
                hashed = hashlib.sha256(f.read(self.block_length)).hexdigest()
                if hashed != hashed_src:
                    # Something fucked up happened
                    return False
        return True

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
        self._compute_random_hashes()

        if not self.is_dangerous:
            self.mime_processing_options.get(self.maintype, self.unknown)()

    # ##### Helper functions #####
    def _make_method_dict(self, list_of_tuples: Tuple) -> Dict[str, Callable]:
        """Returns a dictionary with mimetype: method pairs."""
        dict_to_return = {}
        for list_of_subtypes, method in list_of_tuples:
            for subtype in list_of_subtypes:
                dict_to_return[subtype] = method
        return dict_to_return

    @property
    def has_metadata(self) -> bool:
        """True if filetype typically contains metadata, else False."""
        if self.mimetype in Config.mimes_metadata:
            return True
        return False

    def make_tempdir(self) -> Path:
        """Make a temporary directory at self.tempdir_path."""
        if not self.tempdir_path.exists():
            self.tempdir_path.mkdir(parents=True)
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
                self.force_ext('.txt')
                return
        for mt in Config.mimes_ooxml:
            if mt in self.subtype:
                self._ooxml()
                return
        for mt in Config.mimes_csv:
            if mt in self.subtype:
                self.add_description('CSV file')
                return
        self.add_description('Plain text file')
        self.force_ext('.txt')

    def application(self):
        """Process an application specific file according to its subtype."""
        for subtype, method in self.app_subtype_methods.items():
            if subtype in self.subtype:  # checking for partial matches
                method()
                return
        self._unknown_app()  # if none of the methods match

    def _executables(self):
        """Process an executable file."""
        self.make_dangerous('Executable file')

    def _winoffice(self):
        """Process a winoffice file using olefile/oletools."""
        oid = oletools.oleid.OleID(self.src_path)  # First assume a valid file
        if not olefile.isOleFile(self.src_path):
            # Manual processing, may already count as suspicious
            try:
                ole = olefile.OleFileIO(self.src_path, raise_defects=olefile.DEFECT_INCORRECT)
            except Exception:
                self.make_dangerous('Unparsable WinOffice file')
            if ole.parsing_issues:
                self.make_dangerous('Parsing issues with WinOffice file')
            else:
                if ole.exists('macros/vba') or ole.exists('Macros') \
                        or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                    self.make_dangerous('WinOffice file containing a macro')
        else:
            indicators = oid.check()
            for i in indicators:
                if i.id == 'ObjectPool' and i.value:
                    self.make_dangerous('WinOffice file containing an object pool')
                elif i.id == 'flash' and i.value:
                    self.make_dangerous('WinOffice file with embedded flash')
                elif i.id == 'encrypted' and i.value:
                    self.make_dangerous('Encrypted WinOffice file')
                elif i.id == 'vba_macros' and i.value:
                    self.make_dangerous('WinOffice file containing a macro')

        self.add_description('WinOffice file')

    def _ooxml(self):
        """Process an ooxml file."""
        self.add_description('OOXML (openoffice) file')
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

    def _libreoffice(self):
        """Process a libreoffice file."""
        # As long as there is no way to do a sanity check on the files => dangerous
        try:
            lodoc = zipfile.ZipFile(self.src_path, 'r')
        except Exception:
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
        xmlDoc = PDFiD(str(self.src_path))
        oPDFiD = cPDFiD(xmlDoc, True)
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
    def _metadata_exif(self, metadata_file_path) -> bool:
        """Read exif metadata from a jpg or tiff file using exifread."""
        # TODO: can we shorten this method somehow?
        with open(self.src_path, 'rb') as img:
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
        return True

    def _metadata_png(self, metadata_file_path) -> bool:
        """Extract metadata from a png file using PIL/Pillow."""
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:
            with Image.open(self.src_path) as img:
                for tag in sorted(img.info.keys()):
                    # These are long and obnoxious/binary
                    if tag not in ('icc_profile'):
                        with open(metadata_file_path, 'w+') as metadata_file:
                            metadata_file.write("Key: {}\tValue: {}\n".format(tag, img.info[tag]))
                # LOG: handle metadata
                self.set_property('metadata', 'png')
            return True
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
        if self.has_metadata:
            self.extract_metadata()
        tempdir_path = self.make_tempdir()
        tempfile_path = tempdir_path / self.filename
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        try:  # Do image conversions
            with Image.open(self.src_path) as img_in:
                with Image.frombytes(img_in.mode, img_in.size, img_in.tobytes()) as img_out:
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

    def __init__(self, src_root_path: Path, dst_root_path: Path, debug: bool=False):
        self._src_root_path: Path = src_root_path
        self._dst_root_path: Path = dst_root_path
        self._log_dir_path: Path = self._make_log_dir(dst_root_path)
        self.log_path: Path = self._log_dir_path / 'circlean_log.txt'
        self._add_root_dir(src_root_path)
        if debug:
            self.log_debug_err: Path = self._log_dir_path / 'debug_stderr.log'
            self.log_debug_out: Path = self._log_dir_path / 'debug_stdout.log'
        else:
            self.log_debug_err = Path(os.devnull)
            self.log_debug_out = Path(os.devnull)

    def _make_log_dir(self, root_dir_path: Path) -> Path:
        """Create the directory in the dest dir that will hold the logs"""
        log_dir_path = root_dir_path / 'logs'
        if os.path.exists(log_dir_path):
            shutil.rmtree(log_dir_path)
        os.makedirs(log_dir_path)
        return log_dir_path

    def _add_root_dir(self, root_path: Path):
        """Add the root directory to the log"""
        dirname = os.path.split(root_path)[1] + '/'
        with open(self.log_path, mode='ab') as lf:
            lf.write(bytes(dirname, 'utf-8'))
            lf.write(b'\n')

    def add_file(self, file_path: Path, file_props: dict, in_tempdir: bool=False):
        """Add a file to the log. Takes a path and a dict of file properties."""
        depth = self._get_path_depth(str(file_path))
        try:
            file_hash = Logging.computehash(file_path)[:6]
        except IsADirectoryError:
            file_hash = 'directory'
        except FileNotFoundError:
            file_hash = '------'
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
            log_string += (' Errors: ' + error_string)
        if in_tempdir:
            depth -= 1
        self._write_line_to_log(log_string, depth)

    def add_dir(self, dir_path: Path):
        """Add a directory to the log"""
        path_depth = self._get_path_depth(str(dir_path))
        dirname = os.path.split(str(dir_path))[1] + '/'
        log_line = '+- ' + dirname
        self._write_line_to_log(log_line, path_depth)

    def _format_file_size(self, size: int) -> str:
        """Returns a string with the file size and appropriate unit"""
        file_size = size
        for unit in ('B', 'KB', 'MB', 'GB'):
            if file_size < 1024:
                return str(int(file_size)) + unit
            else:
                file_size = int(file_size / 1024)
        return str(int(file_size)) + 'GB'

    def _get_path_depth(self, path: str) -> int:
        """Returns the relative path depth compared to root directory"""
        if str(self._dst_root_path) in path:
            base_path = str(self._dst_root_path)
        elif str(self._src_root_path) in path:
            base_path = str(self._src_root_path)
        relpath = os.path.relpath(path, base_path)
        path_depth = relpath.count(os.path.sep)
        return path_depth

    def _write_line_to_log(self, line: str, indentation_depth: int):
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

    def __init__(self, root_src: str, root_dst: str, max_recursive_depth: int=2, debug: bool=False):
        super(KittenGroomerFileCheck, self).__init__(root_src, root_dst)
        self.recursive_archive_depth = 0
        self.max_recursive_depth = max_recursive_depth
        self.logger = GroomerLogger(self.src_root_path, self.dst_root_path, debug)

    def __repr__(self):
        return "filecheck.KittenGroomerFileCheck object: {{{}}}".format(
            os.path.basename(self.src_root_path)
        )

    def process_dir(self, src_dir: Path, dst_dir: Optional[Path] = None):
        """Process a directory on the source key."""
        for srcpath in self.list_files_dirs(src_dir):
            if not srcpath.is_symlink() and srcpath.is_dir():
                self.logger.add_dir(srcpath)
            else:
                if dst_dir:
                    dstpath = dst_dir
                else:
                    dstpath = Path(str(srcpath).replace(str(self.src_root_path), str(self.dst_root_path)))
                cur_file = File(srcpath, dstpath)
                self.process_file(cur_file)

    def process_file(self, file: File):
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
                if file.safe_copy():
                    file.set_property('copied', True)
                    if not file._validate_random_hashes():
                        # Something's fucked up.
                        file.make_dangerous('The copied file is different from the one checked, removing.')
                        file.dst_path.unlink()
                else:
                    file.set_property('copied', False)
            self.write_file_to_log(file)
        # TODO: Can probably handle cleaning up the tempdir better
        if hasattr(file, 'tempdir_path'):
            self.safe_rmtree(file.tempdir_path)

    def process_archive(self, file: File):
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
            # -p1=password, x=extract, -o=output location, -bd=no % indicator, -aoa=overwrite existing files
            unpack_command = command_str.format(SEVENZ_PATH,
                                                file.src_path, tempdir_path)
            self._run_process(unpack_command)
            self.write_file_to_log(file)
            self.process_dir(tempdir_path, file.dst_path / file.filename)
            self.safe_rmtree(tempdir_path)
        self.recursive_archive_depth -= 1

    def _run_process(self, command_string: str, timeout: Optional[int]=None) -> bool:
        """Run command_string in a subprocess, wait until it finishes."""
        args = shlex.split(command_string)
        with open(self.logger.log_debug_err, 'ab') as stderr, open(self.logger.log_debug_out, 'ab') as stdout:
            try:
                subprocess.check_call(args, stdout=stdout, stderr=stderr, timeout=timeout)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                return False
        return True

    def write_file_to_log(self, file: File):
        """Pass information about `file` to self.logger."""
        props = file.get_all_props()
        if not file.is_archive:
            # FIXME: in_tempdir is a hack to make image files appear at the correct tree depth in log
            in_tempdir = file.tempdir_path.exists()
            self.logger.add_file(file.src_path, props, in_tempdir)

    def list_files_dirs(self, root_dir_path: Path) -> List[Path]:
        """
        Returns a list of all files and directories

        Performs a depth-first traversal of the file tree.
        """
        skipped_files = ( '.Trashes', '._.Trashes', '.DS_Store', '.fseventsd', '.Spotlight-V100','System Volume Information')
        queue = []
        for path in sorted(os.listdir(root_dir_path), key=lambda x: str.lower(x)):
            full_path = root_dir_path / path
            filename = full_path.name
            if not filename in skipped_files and not filename.startswith('._'):
                # check for symlinks first to prevent getting trapped in infinite symlink recursion
                if full_path.is_symlink():
                    queue.append(full_path)
                elif full_path.is_dir():
                    # Skip hidden and special directories.
                    queue.append(full_path)
                    queue += self.list_files_dirs(full_path)
                elif full_path.is_file():
                    queue.append(full_path)
            else:
                print("SKIPPING: "+filename)
        return queue

    def run(self):
        self.process_dir(self.src_root_path)


def main(kg_implementation, description: str):
    parser = argparse.ArgumentParser(prog='KittenGroomer', description=description)
    parser.add_argument('-s', '--source', type=str, help='Source directory')
    parser.add_argument('-d', '--destination', type=str, help='Destination directory')
    args = parser.parse_args()
    kg = kg_implementation(args.source, args.destination)
    kg.run()


if __name__ == '__main__':
    main(KittenGroomerFileCheck, 'File sanitizer used in CIRCLean. Renames potentially dangerous files.')
