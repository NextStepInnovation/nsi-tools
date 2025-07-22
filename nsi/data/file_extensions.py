from pathlib import Path

def get_ext(file: str | Path) -> str | None:
    file_str = str(file)
    if '.' in file_str:
        ext = file_str.rsplit('.', maxsplit=1)[-1].lower()
        if ext in {'bak', }:
            if file_str.count('.') >= 2:
                ext = file_str.rsplit('.', maxsplit=2)[-2].lower()
        return ext.lower()

def type_from_ext(file: str | Path) -> str | None:
    """
    Provides a dictionary lookup table for common file extensions and their descriptions.
    """

    ext = get_ext(file)
    if (ext is None) or (len(ext) > 5 and ext not in long_ext):
        return None
    return extentions.get(ext)

long_ext = {
    'sketch', 'sqlite', 'torrent', 'unitypackage', 'vbox-debug', 'vbox-extpack',
    'vbox-log', 'vbox-module', 'vbox-ova', 'vbox-ovf', 'vbox-prev', 'vbox-qcow2',
    'vbox-snapshot', 'vbox-vdi', 'vbox-vhd', 'vbox-vmdk'
}

extentions = {
    # Document Files
    "txt": "Plain text file",
    "pdf": "Portable Document Format file",
    "doc": "Microsoft Word Document (older format)",
    "docx": "Microsoft Word Open XML Document",
    "xls": "Microsoft Excel Spreadsheet (older format)",
    "xlsx": "Microsoft Excel Open XML Spreadsheet",
    "ppt": "Microsoft PowerPoint Presentation (older format)",
    "pptx": "Microsoft PowerPoint Open XML Presentation",
    "odt": "OpenDocument Text Document",
    "ods": "OpenDocument Spreadsheet",
    "odp": "OpenDocument Presentation",
    "rtf": "Rich Text Format file",
    "csv": "Comma Separated Values file",

    # Image Files
    "jpg": "JPEG Image file",
    "jpeg": "JPEG Image file",
    "png": "Portable Network Graphics file",
    "gif": "Graphics Interchange Format file",
    "bmp": "Bitmap Image file",
    "tiff": "Tagged Image File Format",
    "tif": "Tagged Image File Format",
    "svg": "Scalable Vector Graphics file",
    "webp": "WebP Image file",
    "ico": "Icon file",

    # Audio Files
    "mp3": "MPEG Audio Layer 3 file",
    "wav": "Waveform Audio File Format",
    "aac": "Advanced Audio Coding file",
    "flac": "Free Lossless Audio Codec file",
    "ogg": "Ogg Vorbis Audio file",
    "wma": "Windows Media Audio file",
    "m4a": "MPEG-4 Audio file",

    # Video Files
    "mp4": "MPEG-4 Video file",
    "avi": "Audio Video Interleave file",
    "mov": "Apple QuickTime Movie file",
    "wmv": "Windows Media Video file",
    "flv": "Flash Video file",
    "webm": "WebM Video file",
    "mkv": "Matroska Video file",
    "3gp": "3GPP Multimedia file",

    # Executable Files
    "exe": "Windows Executable file",
    "app": "macOS Application bundle",
    "bat": "Windows Batch file",
    "sh": "Shell Script",
    "bin": "Binary Executable file",

    # Compressed Files
    "zip": "Zip Compressed file",
    "rar": "Roshal Archive Compressed file",
    "7z": "7-Zip Compressed file",
    "tar": "Tape Archive file",
    "gz": "Gzip Compressed file",
    "bz2": "Bzip2 Compressed file",
    "iso": "Disc Image file",

    # Web Files
    "html": "HyperText Markup Language file",
    "htm": "HyperText Markup Language file",
    "css": "Cascading Style Sheet file",
    "js": "JavaScript file",
    "json": "JavaScript Object Notation file",
    "xml": "Extensible Markup Language file",
    "php": "PHP Hypertext Preprocessor file",
    "asp": "Active Server Page file",
    "aspx": "Active Server Page Extended file",
    "jsp": "JavaServer Pages file",
    "py": "Python Source file",
    "java": "Java Source file",
    "c": "C Source file",
    "cpp": "C++ Source file",
    "h": "C/C++ Header file",
    "cs": "C# Source file",
    "rb": "Ruby Source file",
    "go": "Go Source file",
    "swift": "Swift Source file",
    "kt": "Kotlin Source file",
    "ts": "TypeScript Source file",
    "jsx": "React JavaScript XML file",
    "tsx": "React TypeScript XML file",
    "vue": "Vue.js Single File Component",

    # Database Files
    "db": "Database file (general)",
    "sqlite": "SQLite Database file",
    "sql": "Structured Query Language file",
    "mdb": "Microsoft Access Database (older format)",
    "accdb": "Microsoft Access Database",

    # Font Files
    "ttf": "TrueType Font file",
    "otf": "OpenType Font file",
    "woff": "Web Open Font Format file",
    "woff2": "Web Open Font Format 2.0 file",
    "eot": "Embedded OpenType Font file",

    # Other Common Files
    "ini": "Initialization/Configuration file",
    "log": "Log file",
    "md": "Markdown file",
    "bak": "Backup file",
    "tmp": "Temporary file",
    "url": "Internet Shortcut file",
    "lnk": "Windows Shortcut file",
    "torrent": "BitTorrent file",
    "apk": "Android Package file",
    "ipa": "iOS Application file",
    "dmg": "macOS Disk Image file",
    "iso": "Disc Image file",
    "vcf": "vCard file",
    "ics": "iCalendar file",
    "psd": "Adobe Photoshop Document",
    "ai": "Adobe Illustrator Document",
    "indd": "Adobe InDesign Document",
    "sketch": "Sketch Document",
    "fig": "Figma Design file",
    "xd": "Adobe XD Document",
    "dwg": "AutoCAD Drawing Database file",
    "dxf": "Drawing Exchange Format file",
    "obj": "3D Object file",
    "fbx": "Filmbox 3D file",
    "blend": "Blender 3D file",
    "stl": "Stereolithography 3D file",
    "gltf": "GL Transmission Format 3D file",
    "glb": "Binary GL Transmission Format 3D file",
    "unitypackage": "Unity Package file",
    "pak": "Game Package file",
    "sav": "Game Save file",
    "dll": "Dynamic Link Library",
    "sys": "System file",
    "drv": "Device Driver file",
    "vbs": "VBScript file",
    "ps1": "PowerShell Script file",
    "reg": "Registry file",
    "url": "Internet Shortcut file",
    "xml": "Extensible Markup Language file",
    "yml": "YAML Ain't Markup Language file",
    "yaml": "YAML Ain't Markup Language file",
    "toml": "Tom's Obvious, Minimal Language file",
    "env": "Environment variables file",
    "lock": "Lock file",
    "lic": "License file",
    "pem": "Privacy-Enhanced Mail Certificate file",
    "crt": "Certificate file",
    "cer": "Certificate file",
    "key": "Key file",
    "pfx": "Personal Information Exchange Certificate file",
    "p12": "Personal Information Exchange Certificate file",
    "der": "Distinguished Encoding Rules Certificate file",
    "csr": "Certificate Signing Request file",
    "ovpn": "OpenVPN Configuration file",
    "conf": "Configuration file",
    "cfg": "Configuration file",
    "bak": "Backup file",
    "old": "Old file",
    "temp": "Temporary file",
    "dat": "Data file",
    "bin": "Binary data file",
    "rom": "ROM Image file",
    "nes": "Nintendo Entertainment System ROM",
    "snes": "Super Nintendo Entertainment System ROM",
    "gba": "Game Boy Advance ROM",
    "nds": "Nintendo DS ROM",
    "iso": "Disc Image file",
    "cue": "Cue Sheet file",
    "bin": "Binary Disc Image file",
    "mdf": "Media Disc Image file",
    "mds": "Media Descriptor file",
    "nrg": "Nero Disc Image file",
    "img": "Disk Image file",
    "vhd": "Virtual Hard Disk file",
    "vmdk": "Virtual Machine Disk file",
    "ova": "Open Virtualization Appliance file",
    "ovf": "Open Virtualization Format file",
    "qcow2": "QEMU Copy On Write 2 Disk Image file",
    "vdi": "VirtualBox Disk Image file",
    "box": "VirtualBox Machine file",
    "vmx": "VMware Virtual Machine Configuration file",
    "vbox": "VirtualBox Machine Definition file",
    "vbox-prev": "VirtualBox Previous Machine Definition file",
    "vbox-extpack": "VirtualBox Extension Pack file",
    "vbox-module": "VirtualBox Module file",
    "vbox-log": "VirtualBox Log file",
    "vbox-debug": "VirtualBox Debug Log file",
    "vbox-snapshot": "VirtualBox Snapshot file",
    "vbox-vdi": "VirtualBox Disk Image file",
    "vbox-vmdk": "VirtualBox Disk Image file",
    "vbox-vhd": "VirtualBox Disk Image file",
    "vbox-ova": "VirtualBox Appliance file",
    "vbox-ovf": "VirtualBox Format file",
    "vbox-qcow2": "VirtualBox Disk Image file",
}


