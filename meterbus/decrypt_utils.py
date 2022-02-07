from ctypes import LittleEndianStructure, c_uint8, c_uint16, c_uint32, resize, sizeof, addressof
from .decrypt_keys import key_storages

class UnpackableStructure(LittleEndianStructure):
    _pack_ = 1

    @classmethod
    def from_bytes(cls, buf):
        return cls.from_buffer_copy(bytearray(buf[0:sizeof(cls)]))


class EncryptionMode5ConfigurationField(UnpackableStructure):
    _fields_ = [
        ('HopCounter', c_uint8, 1),
        ('RepeatedAccess', c_uint8, 1),
        ('ContentOfMessage', c_uint8, 2),  # 0=standard unsigned metering 1=signed data 2=static msg (parameters)
        ('EncryptedBlocksCount', c_uint8, 4),
        ('EncryptionMode', c_uint8, 5),
        ('Synchronous', c_uint8, 1),
        ('Accessibility', c_uint8, 1),
        ('Bidirectional', c_uint8, 1)
    ]


class EncryptionMode8or24ConfigurationField(UnpackableStructure):
    _fields_ = [
        ('KeyID', c_uint8, 4),
        ('CNT', c_uint8, 2),
        ('AuthTag2Timestamp', c_uint8, 1),
        ('PartialEncryption', c_uint8, 1),
        ('EncryptionMode', c_uint8, 5),
        ('KDF', c_uint8, 2),
        ('ConfExt', c_uint8, 1)
    ]


class ConfigurationExtField(UnpackableStructure):
    _fields_ = [
        ('ContentField', c_uint8, 2),
        ('KeyVersion', c_uint8, 1),
        ('Reserved', c_uint8, 1),
        ('ContentIndex', c_uint8, 4)
    ]

class ConfigurationField(UnpackableStructure):
    _fields_ = [
        ('ModeSpecific2', c_uint8, 8),
        ('EncryptionMode', c_uint8, 5),
        ('ModeSpecific1', c_uint8, 3)
    ]


def EncryptionMode5DataFactory(configuration_field, buf):
    def EncryptionMode5CreateFields():
        fields = []
        encryptedDataStart = 0
        encryptedDataEnd = len(buf)
        # fields.append(('AESVerify', 2 * c_uint8))
        fields.append(('EncryptedData', c_uint8 * (encryptedDataEnd - encryptedDataStart)))
        return fields

    class EncryptionMode5Data(UnpackableStructure):
        _fields_ = EncryptionMode5CreateFields()

    cf = EncryptionMode5Data.from_bytes(buf)
    return cf


def EncryptionMode8DataFactory(configuration_field, buf):
    def EncryptionMode8CreateFields():
        configurationField = EncryptionMode8or24ConfigurationField.from_buffer(configuration_field)
        fields = []
        encryptedDataStart = 0
        encryptedDataEnd = len(buf) - 4  # includes AuthTag1
        unencryptedDataLen = 0
        if configurationField.ConfExt:
            fields.append(('ConfExt', ConfigurationExtField))
            confExt = ConfigurationExtField.from_bytes([buf[encryptedDataStart]])
            if confExt.KeyVersion:
                encryptedDataStart += 1  # skip keyversion
                fields.append(('KeyVersion', c_uint8))
            encryptedDataStart += 1
        if configurationField.PartialEncryption:
            fields.append(('UnencryptedDataLen', c_uint8))
            unencryptedDataLen = buf[encryptedDataStart]
            encryptedDataEnd -= unencryptedDataLen
        if configurationField.CNT > 0:
            fields.append(('Counter', c_uint8 * (configurationField.CNT + 1)))
            encryptedDataStart += configurationField.CNT + 1
        if configurationField.AuthTag2Timestamp:
            encryptedDataEnd -= 5  # 3 byte timestamp + 2 byte auth tag
        fields.append(('EncryptedData', c_uint8 * (encryptedDataEnd - encryptedDataStart)))
        if configurationField.PartialEncryption:
            fields.append(('UnencryptedData', c_uint8 * unencryptedDataLen))
        fields.append(('AuthTag1', c_uint32))
        if configurationField.AuthTag2Timestamp:
            fields.append(('Timestamp', 3 * c_uint8))  # lowest 24bits of EPOCH2013 timestamp
            fields.append(('AuthTag2', c_uint16))
        return fields

    class EncryptionMode8Data(UnpackableStructure):
        _fields_ = EncryptionMode8CreateFields()

    cf = EncryptionMode8Data.from_bytes(buf)
    cf.Counter = (c_uint8 * 2)(*cf.Counter[::-1])
    return cf


def EncryptionMode24DataFactory(configuration_field, buf):
    def EncryptionMode24CreateFields():
        configurationField = EncryptionMode8or24ConfigurationField.from_buffer(configuration_field)
        fields = []
        encryptedDataStart = 0
        encryptedDataEnd = len(buf) - 4  # includes AuthTag1
        unencryptedDataLen = 0
        if configurationField.ConfExt:
            fields.append(('ConfExt', ConfigurationExtField))
            encryptedDataStart += 1
        if configurationField.PartialEncryption:
            fields.append(('UnencryptedDataLen', c_uint8))
            unencryptedDataLen = buf[encryptedDataStart]
            encryptedDataEnd -= unencryptedDataLen
        if configurationField.CNT > 0:
            fields.append(('Counter', c_uint8 * (configurationField.CNT + 1)))
            encryptedDataStart += configurationField.CNT + 1
        if configurationField.AuthTag2Timestamp:
            encryptedDataEnd -= 5  # 3 byte timestamp + 2 byte auth tag
        fields.append(('EncryptedData', c_uint8 * (encryptedDataEnd - encryptedDataStart)))
        if configurationField.PartialEncryption:
            fields.append(('UnencryptedData', c_uint8 * unencryptedDataLen))
        fields.append(('AuthTag1', c_uint32))
        if configurationField.AuthTag2Timestamp:
            fields.append(('Timestamp', 3 * c_uint8))  # lowest 24bits of EPOCH2013 timestamp
            fields.append(('AuthTag2', c_uint16))
        return fields

    class EncryptionMode24Data(UnpackableStructure):
        _fields_ = EncryptionMode24CreateFields()

    return EncryptionMode24Data.from_bytes(buf)


def decode_configuration(configuration_field):
    data = bytearray(configuration_field.parts[::-1])
    configurationField = ConfigurationField.from_buffer(data)
    if configurationField.EncryptionMode == 5:
        return EncryptionMode5ConfigurationField(data)
    elif configurationField.EncryptionMode == 8:
        return EncryptionMode8or24ConfigurationField(data)
    elif configurationField.EncryptionMode == 24:
        return EncryptionMode8or24ConfigurationField(data)
    return None


def decode_encryption_mode(configuration_field, buf):
    data = bytearray(configuration_field.parts[::-1])
    configurationField = ConfigurationField.from_buffer(data)
    if configurationField.EncryptionMode == 5:
        return EncryptionMode5DataFactory(data, bytearray(buf))
    elif configurationField.EncryptionMode == 8:
        return EncryptionMode8DataFactory(data, bytearray(buf))
    elif configurationField.EncryptionMode == 24:
        return EncryptionMode24DataFactory(data, bytearray(buf))
    return None


def get_module_keys(man, addr):
    storage = key_storages[man]
    if storage is None:
        return None, None
    return storage.get_module_keys(addr)
