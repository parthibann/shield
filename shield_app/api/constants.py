class HttpCodes(object):
    SUCCESS = 200
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    INTERNAL_ERROR = 500


class CertificateTypes(object):
    CA_ROOT = 'ca_root'
    CA_INTEMEDIATE = 'ca_intermediate'
    END_ENTITY = 'end_entity'
    SELF_SIGNED = 'self_signed'
    CERT_TYPES = [CA_ROOT, CA_INTEMEDIATE, END_ENTITY, SELF_SIGNED]


class CertificateStatus(object):
    ACTIVE = 'active'
    INACTIVE = 'in-active'