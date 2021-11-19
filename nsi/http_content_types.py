cat_to_type = {
    'application': [
        'application/java-archive',
        'application/EDI-X12',
        'application/EDIFACT',
        'application/javascript',
        'text/javascript',
        'application/octet-stream',
        'application/ogg',
        'application/pdf',
        'application/xhtml+xml',
        'application/x-shockwave-flash',
        'application/json',
        'application/ld+json',
        'application/xml',
        'application/zip',
        'application/x-www-form-urlencoded',
    ],
    'audio': [
        'audio/mpeg',
        'audio/x-ms-wma',
        'audio/vnd.rn-realaudio',
        'audio/x-wav',
    ],
    'image': [
        'image/gif',
        'image/jpeg',
        'image/png',
        'image/tiff',
        'image/vnd.microsoft.icon',
        'image/x-icon',
        'image/vnd.djvu',
        'image/svg+xml',
    ],
    'multipart': [
        'multipart/mixed',
        'multipart/alternative',
        'multipart/related',
        'multipart/form-data',
    ],
    'text': [
        'text/css',
        'text/csv',
        'text/html',
        'text/plain',
        'text/xml',
    ],
    'video': [
        'video/mpeg',
        'video/mp4',
        'video/quicktime',
        'video/x-ms-wmv',
        'video/x-msvideo',
        'video/x-flv',
        'video/webm',
    ],
    'vnd': [
        'application/vnd.android.package-archive',
        'application/vnd.oasis.opendocument.text',
        'application/vnd.oasis.opendocument.spreadsheet',
        'application/vnd.oasis.opendocument.presentation',
        'application/vnd.oasis.opendocument.graphics',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.'
        'presentationml.presentation',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.'
        'wordprocessingml.document',
        'application/vnd.mozilla.xul+xml',
    ],
}

type_to_cat = {
    t: c for t in cat_to_type for c in cat_to_type[t]
}

def category(ctype: str):
    return type_to_cat.get(ctype.lower, ctype.split('/'))

def is_javascript(ctype: str):
    return 'javascript' in ctype.lower()

def is_html(ctype: str):
    return 'html' in ctype.lower()

def is_json(ctype: str):
    return 'json' in ctype.lower()
