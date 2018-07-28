import os
import json
import logging
from bson import ObjectId
from collections import OrderedDict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import datetime
import time

from shield_app.utils import common
from shield_app.api.constants import HttpCodes
from shield_app.api.constants import CertificateTypes
from shield_app.api.constants import CertificateStatus
from shield_app.db.pymongodb import KeypairDBAPI
from shield_app.db.pymongodb import CertificatesDBAPI


LOG = logging.getLogger(__name__)


class ValidateSchema(object):
    def __init__(self, data):
        self.data = data

    def common_name(self):
        field_name = 'common_name'
        if field_name not in self.data or not self.data[field_name]:
            raise Exception('%s is mandatory and it cant be empty.' % field_name)
        return str(self.data.get(field_name))

    def cert_type(self):
        field_name = 'cert_type'
        if field_name not in self.data or not self.data[field_name]:
            raise Exception('%s is mandatory and it cant be empty.' % field_name)
        if self.data[field_name] not in CertificateTypes.CERT_TYPES:
            raise Exception('Invalid Certificate type, certificate type can be any one of the following: %s' %
                            ', '.join(CertificateTypes.CERT_TYPES))
        return str(self.data.get(field_name))

    def country(self):
        field_name = 'country'
        country = self.data.get(field_name)
        return str(country) if country else country

    def state(self):
        field_name = 'state'
        state = self.data.get(field_name)
        return str(state) if state else state

    def locality(self):
        field_name = 'locality'
        locality = self.data.get(field_name)
        return str(locality) if locality else locality

    def organization_name(self):
        field_name = 'organization_name'
        org_name = self.data.get(field_name)
        return str(org_name) if org_name else org_name

    def organization_unit_name(self):
        field_name = 'organization_unit_name'
        org_unit_name = self.data.get(field_name)
        return str(org_unit_name) if org_unit_name else org_unit_name

    def valid_till(self):
        field_name = 'valid_till'
        if field_name not in self.data or not self.data[field_name]:
            raise Exception('%s is mandatory and it cant be empty.' % field_name)
        try:
            end_time = datetime.datetime.strptime(self.data[field_name], '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            raise ValueError("Incorrect valid_till format, should be YYYY-MM-DDTH:M:S")
        return end_time

    def valid_from(self):
        field_name = 'valid_from'
        if field_name not in self.data or not self.data[field_name]:
            raise Exception('%s is mandatory and it cant be empty.' % field_name)
        try:
            start_time = datetime.datetime.strptime(self.data[field_name], '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            raise ValueError("Incorrect valid_from format, should be YYYY-MM-DDTH:M:S")
        return start_time

    def subject_alternate_name(self):
        field_name = 'subject_alternate_name'
        sub_alt_name = self.data.get(field_name)
        return str(sub_alt_name) if sub_alt_name else sub_alt_name

    def ca(self):
        certificate_type = self.cert_type()
        if certificate_type != CertificateTypes.END_ENTITY:
            ca = True
        else:
            ca = False
        return ca

    def path_length(self):
        field_name = 'path_length'
        path_length = self.data.get(field_name)
        try:
            path_length = int(path_length)
        except ValueError:
            path_length = path_length
        if not self.ca() or not path_length:
            path_length = None
        elif not isinstance(path_length, int):
            raise Exception('Invalid %s. %s must be an integer value' % (field_name, field_name))
        return int(path_length) if path_length else path_length

    def issuer_id(self):
        field_name = 'issuer_id'
        cert_type = self.cert_type()
        if cert_type in [CertificateTypes.END_ENTITY, CertificateTypes.CA_INTEMEDIATE]:
            if not self.data.get(field_name):
                raise Exception('%s is mandatory for %s / %s certificate types and it cant be empty.' %
                                (field_name, CertificateTypes.CA_INTEMEDIATE, CertificateTypes.END_ENTITY))
        if self.data.get(field_name):
            try:
                ObjectId(self.data.get(field_name))
            except Exception:
                raise Exception('Invalid issuer_id specified.')
        return self.data.get(field_name)

    def signature_algorithm(self):
        field_name = 'signature_algorithm'
        if field_name not in self.data or not self.data[field_name]:
            return 'sha256'
        if self.data[field_name] and self.data[field_name] not in ['sha1', 'sha256']:
            raise Exception('Signature algorithm should be sha1 or sha256.')
        return self.data.get(field_name)


class CertificateActions(object):

    def __init__(self):
        self.keypair_db = KeypairDBAPI()
        self.certificate_db = CertificatesDBAPI()

    def schema_validation(self, req_body):
        sch_data = ValidateSchema(req_body)
        data = dict()
        data['common_name'] = sch_data.common_name()
        data['valid_from'] = sch_data.valid_from()
        data['valid_till'] = sch_data.valid_till()
        data['ca'] = sch_data.ca()
        data['cert_type'] = sch_data.cert_type()
        data['path_length'] = sch_data.path_length()
        data['issuer_id'] = sch_data.issuer_id()
        data['locality'] = sch_data.locality()
        data['state'] = sch_data.state()
        data['country'] = sch_data.country()
        data['subject_alternate_name'] = sch_data.subject_alternate_name()
        data['organization_unit_name'] = sch_data.organization_unit_name()
        data['organization_name'] = sch_data.organization_name()
        data['signature_algorithm'] = sch_data.signature_algorithm()
        return data

    def create(self, req_body):
        try:
            cert_data = dict()
            data = ValidateSchema(req_body)
            key_name = data.common_name() + '_' + str(datetime.datetime.strftime(datetime.datetime.utcnow(),
                                                                                 '%Y%m%d%H%M%S'))
            self.schema_validation(req_body)
            key_id = self.create_and_save_keypair(key_name)
            keypair_query = {'_id': ObjectId(key_id)}
            key_details = self.keypair_db.get_keypair(keypair_query)
            keypair = str(key_details.get('keypair'))
            certificate_type = data.cert_type()
            ca = data.ca()
            issuer_id = data.issuer_id()
            issuer_crt = None
            issuer_key = None
            issuer_key_id = None
            if issuer_id:
                issuer_query = dict()
                issuer_query['_id'] = ObjectId(issuer_id)
                issuer_details = self.certificate_db.get_certificate(issuer_query)
                issuer_crt = str(issuer_details.get('certificate'))
                issuer_key_id = str(issuer_details.get('key_id'))
            if issuer_key_id:
                issuer_key_query = dict()
                issuer_key_query['_id'] = ObjectId(issuer_key_id)
                issuer_key_details = self.keypair_db.get_keypair(issuer_key_query)
                issuer_key = str(issuer_key_details.get('keypair'))
            cert = self.create_certificate(common_name=data.common_name(), private_key=keypair,
                                           start_time=data.valid_from(), locality=data.locality(),
                                           org_name=data.organization_name(), ca=ca, end_time=data.valid_till(),
                                           subject_alt_name=data.subject_alternate_name(), issuer_crt=issuer_crt,
                                           path_length=data.path_length(), country=data.country(), state=data.state(),
                                           org_unit_name=data.organization_unit_name(), issuer_key=issuer_key)
            cert_data['common_name'] = data.common_name()
            cert_data['country'] = data.country()
            cert_data['state'] = data.state()
            cert_data['locality'] = data.locality()
            cert_data['organization_name'] = data.organization_name()
            cert_data['organization_unit_name'] = data.organization_unit_name()
            cert_data['key_id'] = str(key_id)
            cert_data['valid_from'] = data.valid_from()
            cert_data['valid_till'] = data.valid_till()
            cert_data['subject_alternative_name'] = data.subject_alternate_name()
            cert_data['ca'] = ca
            cert_data['path_length'] = data.path_length()
            cert_data['issuer_id'] = data.issuer_id()
            cert_data['signature_algorithm'] = data.signature_algorithm()
            cert_data['certificate'] = cert
            cert_data['certificate_type'] = certificate_type
            cert_data['status'] = CertificateStatus.ACTIVE
            cert_id = self.certificate_db.create_certificates(cert_data)

            status = HttpCodes.SUCCESS
            LOG.info('200 - Certificate created successfully')
            res_body = dict(status='success',
                            message='Certificate created successfully.',
                            id=str(cert_id))
            return [status, json.dumps(res_body)]
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def view(self, cert_id):
        try:
            query = {'_id': ObjectId(cert_id)}
            cert_details = self.certificate_db.get_certificate(query)
            if cert_details:
                data = dict()
                data['id'] = str(cert_details.get('_id'))
                data['common_name'] = cert_details.get('common_name')
                data['created_at'] = str(cert_details.get('created_at'))
                data['country'] = cert_details.get('country')
                data['locality'] = cert_details.get('locality')
                data['path_length'] = cert_details.get('path_length')
                data['valid_from'] = str(cert_details.get('valid_from'))
                data['valid_till'] = str(cert_details.get('valid_till'))
                data['issuer_id'] = cert_details.get('issuer_id')
                data['organization_name'] = cert_details.get('organization_name')
                data['organization_unit_name'] = cert_details.get('organization_unit_name')
                data['signature_algorithm'] = cert_details.get('signature_algorithm')
                data['certificate_type'] = cert_details.get('certificate_type')
                data['status'] = cert_details.get('status')
                LOG.info('200 - Certificate view')
                status = HttpCodes.SUCCESS
                res_body = dict(status='success',
                                message='Certificate information',
                                data=data)
            else:
                LOG.info('404 - Certificate not found')
                status = HttpCodes.NOT_FOUND
                res_body = dict(status='error',
                                message='Certificate not found.')
            return [status, json.dumps(res_body)]
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def get_calist(self):
        ca_details = dict()
        ca_details["self_signed"] = list()
        ca_details["ca_root"] = list()
        certificates = self.certificate_db.get_certificates(
            {"certificate_type": {"$in": [CertificateTypes.CA_ROOT, CertificateTypes.CA_INTEMEDIATE]}})
        ca_certificates = self.certificate_db.get_certificates(
            {"path_length": {"$gt": 0}, "certificate_type":
                {"$in": [CertificateTypes.CA_ROOT, CertificateTypes.CA_INTEMEDIATE]}})
        end_entity = list()
        for certificate in certificates:
            cert_dict = dict()
            cert_dict["id"] = str(certificate["_id"])
            cert_dict["name"] = certificate["common_name"]
            end_entity.append(cert_dict)
        ca_details["end_entity"] = end_entity
        ca_inter = list()
        for cert in ca_certificates:
            cert_dict = dict()
            cert_dict["id"] = str(cert["_id"])
            cert_dict["name"] = cert["common_name"]
            ca_inter.append(cert_dict)
        ca_details["ca_intermediate"] = ca_inter
        return ca_details

    def list(self, request_args):
        limit = 0
        page_count = 1
        skip_val = 0
        page = 0
        cert_list = list()
        try:
            total_certificates = self.certificate_db.get_certificates({}).count()
            if request_args:
                skip_val = int(request_args.get('skip_val', 0))
                page = int(request_args.get('page', 0))
                limit = int(request_args.get('limit', 0))
                action = request_args.get('action', None)
                if action and action == 'calist':
                    ca_list = self.get_calist()
                    LOG.info('200 - CA list')
                    status = HttpCodes.SUCCESS
                    return [status, json.dumps(ca_list)]
            skip_val, limit, page_count = common.pagination(limit, page, total_certificates, page_count, skip_val)
            certificates = self.certificate_db.get_certificates({}, skip_val=skip_val, limit=limit)
            for certificate in certificates:
                cert_dict = OrderedDict([
                    ("id", str(certificate["_id"])),
                    ("common_name", certificate["common_name"]),
                    ("cert_type", certificate["certificate_type"]),
                    ("signature_algorithm", certificate["signature_algorithm"]),
                    ("valid_from", str(certificate["valid_from"])),
                    ("valid_till", str(certificate["valid_till"])),
                    ("key_id", certificate["key_id"]),
                    ("issuer_id", certificate["issuer_id"])
                ])
                cert_list.append(cert_dict)
            LOG.info('200 - Certificates list')
            if not limit:
                limit = total_certificates
            status = HttpCodes.SUCCESS
            res_body = dict(status='success',
                            message='Certificates list',
                            recordsTotal=total_certificates,
                            draw=1,
                            recordsFiltered=limit,
                            page_count=page_count,
                            data=dict(certificates=cert_list))
            return [status, json.dumps(res_body)]
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def delete(self, cert_id):
        try:
            query = {'_id': ObjectId(cert_id)}
            cert_details = self.certificate_db.get_certificate(query)
            if cert_details:
                update_data = {'status': CertificateStatus.INACTIVE}
                self.certificate_db.delete(cert_id, update_data)
                LOG.info('200 - Certificate delete')
                status = HttpCodes.SUCCESS
                res_body = dict(status='success',
                                message='Certificate deleted successfully.')
            else:
                LOG.info('404 - Certificate not found')
                status = HttpCodes.NOT_FOUND
                res_body = dict(status='error',
                                message='Certificate not found.')
            return [status, json.dumps(res_body)]
        except Exception as e:
            LOG.error(e.message)
            raise Exception(e.message)

    def create_keypair(self, key_length=2048):
        """
        To create the keypair
        :param key_length: length of the keypair
        :return: private key, public key
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_length, backend=default_backend())
        public_key = private_key.public_key()
        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption())
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.PKCS1)
        return private_key_pem, public_key_pem

    def create_and_save_keypair(self, keyname=None):
        """
        To create and save the keypair.
        :return:
        """
        keypair_details = dict()
        key_length = 2048
        private_key, public_ley = self.create_keypair(key_length=key_length)
        keypair_details['keypair'] = private_key
        keypair_details['public_key'] = public_ley
        keypair_details['key_length'] = key_length
        keypair_details['key_name'] = keyname
        key_id = self.keypair_db.create_keypair(keypair_details)
        return str(key_id)

    def create_certificate(self, common_name, private_key, start_time, end_time, country=None, state=None,
                           locality=None, org_name=None, org_unit_name=None, subject_alt_name=None, ca=False,
                           path_length=None, issuer_key=None, issuer_crt=None, signature_algorithm='sha256'):
        """
        To generate certificate with the given parameters.
        :param common_name: common name of the certificate
        :param issuer_crt: certificate of the issuer
        :param private_key: private key
        :param country: country name
        :param state: state name
        :param locality: locality name
        :param org_name: organization name
        :param org_unit_name: organizational unit name
        :param end_time: validity end time
        :param start_time: validity start time.
        :param subject_alt_name: subject alternative name
        :param ca: boolean value to say it is a certificate authority or not
        :param path_length: no of intermediate CA's to follow
        :param issuer_key: issuer's private key
        :param signature_algorithm: certificate signing signature algorithm
        :return: certificate pem format
        """
        if signature_algorithm == 'sha256':
            alg = hashes.SHA256()
        else:
            alg = hashes.SHA1()
        if not subject_alt_name:
            subject_alt_name = [common_name]
        if not isinstance(subject_alt_name, list):
            subject_alt_name = [subject_alt_name]
        private_key = load_pem_private_key(private_key, None, default_backend())
        if not issuer_key:
            issuer_key = private_key
        else:
            issuer_key = load_pem_private_key(issuer_key, None, default_backend())
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()

        subject_details = list()
        subject_details.append(x509.NameAttribute(NameOID.COMMON_NAME, unicode(common_name, "utf-8")))
        if country:
            subject_details.append(x509.NameAttribute(NameOID.COUNTRY_NAME, unicode(country, "utf-8")))
        if state:
            subject_details.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, unicode(state, "utf-8")))
        if locality:
            subject_details.append(x509.NameAttribute(NameOID.LOCALITY_NAME, unicode(locality, "utf-8")))
        if org_name:
            subject_details.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, unicode(org_name, "utf-8")))
        if org_unit_name:
            subject_details.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unicode(org_unit_name, "utf-8")))

        builder = builder.subject_name(x509.Name(subject_details))

        if ca and issuer_crt:
            issuer_crt_details = x509.load_pem_x509_certificate(issuer_crt, default_backend())
            issuer_details = issuer_crt_details.subject
        elif issuer_crt and not path_length:
            issuer_crt_details = x509.load_pem_x509_certificate(issuer_crt, default_backend())
            issuer_details = issuer_crt_details.subject
        else:
            issuer_details = subject_details
        builder = builder.issuer_name(x509.Name(issuer_details))

        builder = builder.not_valid_before(start_time)
        builder = builder.not_valid_after(end_time)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        for each_alt_name in subject_alt_name:
            builder = builder.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(unicode(each_alt_name, "utf-8"))]), critical=False)
        if ca:
            builder = builder.add_extension(
                x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True,
                              data_encipherment=True, key_agreement=True, key_cert_sign=True,
                              crl_sign=True, encipher_only=True, decipher_only=True), critical=True)
        else:
            builder = builder.add_extension(
                x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=True,
                              data_encipherment=True, key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True, )
        certificate = builder.sign(private_key=issuer_key, algorithm=alg, backend=default_backend())
        certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM, )
        return certificate_pem

    def wipe_unused(self, basedir, limit):
        """
        Remove files in *basedir* not accessed within *limit* minutes
        :param basedir: directory to clean
        :param limit: minutes
        """
        atime_limit = time.time() - limit
        count = 0
        for filename in os.listdir(basedir):
            path = os.path.join(basedir, filename)
            if os.path.getatime(path) < atime_limit:
                os.remove(path)
                count += 1
        LOG.debug("Removed {} temporary files.".format(count))

    # def download(self, resource_id, type):
    #     """
    #     To download files
    #     :param resource_id: id of the resource(certificate / keypair)
    #     :param type: cert / public_key / private_key
    #     :return: certificate
    #     """
    #     filename = None
    #     current_path = os.path.dirname(os.path.abspath(__file__))
    #     tmp_path = os.path.join(current_path, os.pardir, os.pardir, 'tmp')
    #     self.wipe_unused(tmp_path, 1 * 60)  # delete files older than 1 minutes in tmp directory
    #     if type == 'cert':
    #         resource = self.certificate_db.get_certificate({'_id': ObjectId(resource_id)})
    #         if resource:
    #             data = str(resource.get('certificate'))
    #             filename = os.path.join(tmp_path, 'cert' + '_' + str(resource.get("_id")) + '.pem')
    #             with open(filename, 'wb') as pem_out:
    #                 pem_out.write(data)
    #     elif 'key' in type:
    #         resource = self.keypair_db.get_keypair({'_id': ObjectId(resource_id)})
    #         if resource:
    #             if type == 'private_key':
    #                 data = str(resource.get('keypair'))
    #                 filename = os.path.join(tmp_path, 'private_key' + '_' + str(resource.get("_id")) + '.pem')
    #                 with open(filename, 'wb') as pem_out:
    #                     pem_out.write(data)
    #             elif type == 'public_key':
    #                 data = str(resource.get('public_key'))
    #                 filename = os.path.join(tmp_path, 'public_key' + '_' + str(resource.get("_id")) + '.pem')
    #                 with open(filename, 'wb') as pem_out:
    #                     pem_out.write(data)
    #     else:
    #         filename = None
    #     return filename

    def download(self, resource_id, resource_type):
        """
        To download files
        :param resource_id: id of the resource(certificate / keypair)
        :param resource_type: cert / public_key / private_key
        :return: certificate
        """
        data = ''
        if resource_type == 'cert':
            resource = self.certificate_db.get_certificate({'_id': ObjectId(resource_id)})
            if resource:
                data = str(resource.get('certificate'))
        elif'key' in resource_type:
            resource = self.keypair_db.get_keypair({'_id': ObjectId(resource_id)})
            if resource:
                if resource_type == 'private_key':
                    data = str(resource.get('keypair'))
                elif resource_type == 'public_key':
                    data = str(resource.get('public_key'))
                else:
                    raise Exception("Invalid type")
        else:
            raise Exception("Specified resource %s of type %s not found" % (str(resource_id), resource_type))
        return data
