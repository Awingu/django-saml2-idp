# Portions borrowed from:
# http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations  # noqa
import uuid
import zlib
import codecs


def decode_base64_and_inflate(b64string):
    """Decode and uncompress a base64 encoded string."""
    if not isinstance(b64string, bytes):
        b64string = b64string.encode('utf-8')
    decoded_data = codecs.decode(b64string, 'base64')
    return zlib.decompress(decoded_data, -15)


def deflate_and_base64_encode(string_val):
    """Base64 encode and compress a string."""
    if not isinstance(string_val, bytes):
        string_val = string_val.encode('utf-8')
    zlibbed_str = zlib.compress(string_val)
    compressed_string = zlibbed_str[2:-4]
    return codecs.encode(compressed_string, 'base64')


def nice64(src):
    """ Returns src base64-encoded and formatted nicely for our XML. """
    if not isinstance(src, bytes):
        src = src.encode('utf-8')
    return codecs.encode(src, 'base64').decode('utf-8').replace('\n', '')


def convert_guid_to_immutable_id(object_guid):
    """
    Converts an AD ObjectGUID to Office 365 ImmutableID.

    ref: http://gallery.technet.microsoft.com/office/Covert-DirSyncMS-Online-5f3563b1#content  # noqa

    >> object_guid = '1f478d69-8585-4bee-89f6-a772287e6449'
    >> convert_guid_to_immutable_id(object_guid)
    >> 'aY1HH4WF7kuJ9qdyKH5kSQ=='

    :param object_guid: ObjectGUID string or ObjectGUID UUID instance.
        example: '1f478d69-8585-4bee-89f6-a772287e6449'
        or: UUID('1f478d69-8585-4bee-89f6-a772287e6449')

    :return: ImmutableID string.
    """
    guid = object_guid
    if not isinstance(object_guid, uuid.UUID):
        guid = uuid.UUID(object_guid)

    return codecs.encode(guid.bytes_le, 'base64').decode('utf-8').strip('\n')
