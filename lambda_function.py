import json
import base64
import logging
import time
import urllib.request as urllib
from jose import jwk, jwt
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def lambda_handler(event, context):
    logging.info('Event: {}'.format(json.dumps(event)))
    signatureValid = False
    notExpired = False
    matchingKeyFound = False
    try:
        if not 'token' in event or len(event['token']) == 0:
            raise Exception('The key \'token\' is required.')
        logger.info('Separating header, payload, and signature in the JWT...')
        jwt_header, jwt_payload, jwt_signature = event['token'].rsplit('.', 2)
        logger.info('Raw header: {}'.format(jwt_header))
        logger.info('Raw payload: {}'.format(jwt_payload))
        logger.info('Raw signature: {}'.format(jwt_signature))
        jwt_header_decoded = json.loads(
            base64.b64decode(jwt_header + '====').decode('utf-8'))
        logger.info('Decoded JWT header: {}'.format(
            json.dumps(jwt_header_decoded)))
        jwt_payload_decoded = json.loads(
            base64.b64decode(jwt_payload + '====').decode('utf-8'))
        logger.info('Decoded JWT payload: {}'.format(
            json.dumps(jwt_payload_decoded)))
        jwt_signature_decoded = base64.urlsafe_b64decode(
            jwt_signature.encode('utf-8') + b'====')
        logger.info('Decoded JWT signature bytes: {}'.format(
            jwt_signature_decoded))
        jwks = json.loads(urllib.urlopen(
            jwt_payload_decoded['iss'] + '/.well-known/jwks.json').read())['keys']
        logger.info('JWKs: {}'.format(json.dumps(jwks)))
        kid = jwt_header_decoded['kid']
        logger.info('Key ID: {}'.format(kid))
        logger.info('Finding key ID obtained from the JWT with issuer JWKs...')
        for i in range(len(jwks)):
            if kid == jwks[i]['kid']:
                public_key = jwk.construct(jwks[i])
                matchingKeyFound = True
                break
        if matchingKeyFound == False:
            logger.error('Key not found.')
            Exception('Key not found.')
        logger.info('Key found.')
        logger.info('Verifying signature...')
        if public_key.verify((jwt_header + '.' + jwt_payload).encode('utf-8'), jwt_signature_decoded):
            signatureValid = True
            logger.info('JWT signature is successfully verified.')
        else:
            signatureValid = False
            logger.error('JWT signature verification is failed.')
            raise Exception('JWT signature verification is failed.')
        logger.info('Verifying expiration timestamp...')
        if time.time() > jwt_payload_decoded['exp']:
            notExpired = False
            logger.error('The JWT is expired at {}'.format(time.strftime(
                '%Y-%m-%dT%H:%M:%SZ', time.gmtime(jwt_payload_decoded['exp']))))
            raise Exception('The JWT is expired at {}'.format(time.strftime(
                '%Y-%m-%dT%H:%M:%SZ', time.gmtime(jwt_payload_decoded['exp']))))
        else:
            notExpired = True
            logger.info('JWT is valid until {}. Verification completed.'.format(
                time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(jwt_payload_decoded['exp']))))
            response = {
                'statusCode': 200,
                'body': {
                    'header': jwt_header_decoded,
                    'payload': jwt_payload_decoded,
                    'signatureValid': signatureValid,
                    'notExpired': notExpired,
                    'matchingKeyFound': matchingKeyFound
                }
            }
            return response
    except UnicodeDecodeError as e:
        logger.error('{}: {}. Is the token encoded in JWT?'.format(
            type(e).__name__, e))
        error_msg = '{}: {}. Is the token encoded in JWT?'.format(
            type(e).__name__, e)
        return {
            'statusCode': 502,
            'body': {
                'Error': error_msg,
                'signatureValid': signatureValid,
                'notExpired': notExpired,
                'matchingKeyFound': matchingKeyFound
            }
        }
    except Exception as e:
        logger.error('{}: {}'.format(type(e).__name__, e))
        error_msg = str(e)
        return {
            'statusCode': 502,
            'body': {
                'Error': error_msg,
                'signatureValid': signatureValid,
                'notExpired': notExpired,
                'matchingKeyFound': matchingKeyFound
            }
        }
