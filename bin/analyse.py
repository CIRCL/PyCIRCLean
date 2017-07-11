#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import mimetypes
import subprocess
import zipfile

import oletools.oleid
import olefile
import officedissector
import warnings
import exifread
from PIL import Image
# TODO: why do we have this import? How does filecheck handle pngs?
# from PIL import PngImagePlugin
from pdfid import PDFiD, cPDFiD
from kittengroomer import FileBase

CLAMDSCAN = "/usr/local/bin/clamdscan"

class Config:
    """Configuration information for Filecheck."""

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
    
    # Compressed files susceptible to have double extension
    double_exts = (".uzip", ".lzma", ".z", ".xz", ".lz", ".gz2", ".gz",
                       ".bz2", ".pack", ".rar", ".000")

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

    # Forbidden char in filename
    dangerous_char = ("\\", "/", "<", ">", "%", "*", "~", "?", "$", ":", ";", ".", " ", u"\u202E")
    
    # Only char accepted in filename
    accepted_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ-abcdefghijklmnopqrstuvwxyzàéôù_0123456789"

    # Attention aux options
    script_endline = ("sh", "bash", "dash", "python", "perl")
    script_firstchar = ("#")

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

    ignored_mimes = ['inode', 'model', 'multipart', 'example']
    
    archive_timeout = None




class File(FileBase):

    def __init__(self, src_path, dst_path, logger):
        super(File, self).__init__(src_path, dst_path)
        self.is_recursive = False
        self.logger = logger
        self.tempdir_path = self.dst_path + '_temp'

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
        if not self.has_mimetype:
            self.make_dangerous('File has no mimetype')
        if not self.has_extension:
            self.make_dangerous('File has no extension')
        if self.extension in Config.malicious_exts:
            self.make_dangerous('Extension identifies file as potentially dangerous')

    def _check_extension(self):
        """
        Guess the file's mimetype based on its extension.

        If the file's mimetype (as determined by libmagic) is contained in
        the `mimetype` module's list of valid mimetypes and the expected
        mimetype based on its extension differs from the mimetype determined
        by libmagic, then mark the file as dangerous.
        """
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
        Delete forbidden characters to avoid name obfuscation (see class Config).
        
        Delete dots to avoid double extensions.
        """
        dir_path, file = os.path.split(self.dst_path)
        name, ext = os.path.splitext(self.filename)
        
        if not self.extension in Config.double_exts:
            for c in name:    
                if c in Config.accepted_char :
                    self.make_dangerous('Filename contains forbidden character')
                    name = name.replace(c, '-')

        # TODO: change self.filename and'filename' property? Or should those reflect the values on the source key
        self.dst_path = os.path.join(dir_path, name + ext)
                

    def check(self):
        if self.main_type in Config.ignored_mimes:
            self.should_copy = False
            self.mime_processing_options.get(self.main_type, self.unknown)()
        else:
            self._check_dangerous()
            self._check_filename()
            if self.has_extension:
                self._check_extension()
            if self.has_mimetype:
                self._check_mimetype()
            if not self.is_dangerous:
                self.mime_processing_options.get(self.main_type, self.unknown)()

    def write_log(self):
        props = self.get_all_props()
        if not self.is_recursive:
            if os.path.exists(self.tempdir_path):
                # Hack to make images appear at the correct tree depth in log
                self.logger.add_file(self.src_path, props, in_tempdir=True)
                return
        self.logger.add_file(self.src_path, props)

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

    def unknown(self):
        """Main type should never be unknown."""
        self.add_description('Unknown mimetype')

    def example(self):
        """Used in examples, should never be returned by libmagic."""
        self.add_description('Example file')

    def multipart(self):
        """Used in web apps, should never be returned by libmagic"""
        self.add_description('Multipart file - usually found in web apps')

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
            if mt in self.sub_type:
                self.add_description('Rich Text (rtf) file')
                # TODO: need a way to convert it to plain text
                self.force_ext('.txt')
                return
        for mt in Config.mimes_ooxml:
            if mt in self.sub_type:
                self.add_description('OOXML (openoffice) file')
                self._ooxml()
                return
        self.add_description('Plain text file')
        self.force_ext('.txt')

    def application(self):
        """Process an application specific file according to its subtype."""
        for subtype, method in self.app_subtype_methods.items():
            if subtype in self.sub_type:
                # TODO: should we change the logic so we don't iterate through all of the subtype methods?
                # TODO: should these methods return a value?
                method()
                return
        self._unknown_app()

    def _executables(self):
        """Process an executable file."""
        # LOG: change the processing_type property to some other name or include in file_string
        self._clamdscan()
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
                    # TODO: is having an ObjectPool suspicious?
                    # LOG: user defined property
                    self.add_description('WinOffice file containing an object pool')
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
            self.add_description('OOXML file')

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
        self.is_recursive = True

    def _unknown_app(self):
        """Process an unknown file."""
        self.add_description('Unknown application file')
        self.make_unknown()

    def _binary_app(self):
        """Process an unknown binary file."""
        self.add_description('Unknown binary file')
        self.make_binary()

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
            
    def _clamdscan(self):
        """
        Scan a file with ClamAV. Requires clamd to be running.
        """
        output = subprocess.Popen([CLAMDSCAN, self.src_path], stdout = subprocess.PIPE).communicate()[0]
        check = output.split(b'\n')[0].split(b': ')[1]
        if b'OK' not in check:
            make_dangerous('File has been detected as a virus')

