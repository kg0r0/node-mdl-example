import { DeviceResponse } from "@auth0/mdl";
import { MDoc, Document } from "@auth0/mdl";
import { JWK } from 'jose';
import { inspect } from "node:util";
import cbor from 'cbor';

(async () => {
  let issuerMDoc;
  let deviceResponseMDoc;

  const ISSUER_PRIVATE_KEY_JWK: JWK = {
    kty: 'EC',
    kid: '1234',
    x: 'iTwtg0eQbcbNabf2Nq9L_VM_lhhPCq2s0Qgw2kRx29s',
    y: 'YKwXDRz8U0-uLZ3NSI93R_35eNkl6jHp6Qg8OCup7VM',
    crv: 'P-256',
    d: 'o6PrzBm1dCfSwqJHW6DVqmJOCQSIAosrCPfbFJDMNp4',
  };

  const DEVICE_JWK = {
    kty: 'EC',
    x: 'iBh5ynojixm_D0wfjADpouGbp6b3Pq6SuFHU3htQhVk',
    y: 'oxS1OAORJ7XNUHNfVFGeM8E0RQVFxWA62fJj-sxW03c',
    crv: 'P-256',
    d: 'eRpAZr3eV5xMMnPG3kWjg90Y-bBff9LqmlQuk49HUtA',
  };

  const ISSUER_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIICKjCCAdCgAwIBAgIUV8bM0wi95D7KN0TyqHE42ru4hOgwCgYIKoZIzj0EAwIw
UzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMQ8wDQYDVQQHDAZBbGJh
bnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UECwwGTlkgRE1WMB4XDTIzMDkxNDE0
NTUxOFoXDTMzMDkxMTE0NTUxOFowUzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
dyBZb3JrMQ8wDQYDVQQHDAZBbGJhbnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UE
CwwGTlkgRE1WMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTwtg0eQbcbNabf2
Nq9L/VM/lhhPCq2s0Qgw2kRx29tgrBcNHPxTT64tnc1Ij3dH/fl42SXqMenpCDw4
K6ntU6OBgTB/MB0GA1UdDgQWBBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAfBgNVHSME
GDAWgBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAPBgNVHRMBAf8EBTADAQH/MCwGCWCG
SAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAKBggqhkjO
PQQDAgNIADBFAiAJ/Qyrl7A+ePZOdNfc7ohmjEdqCvxaos6//gfTvncuqQIhANo4
q8mKCA9J8k/+zh//yKbN1bLAtdqPx7dnrDqV3Lg+
-----END CERTIFICATE-----`;



  // This is what the MDL issuer does to generate a credential:
  {
    const issuerPrivateKey = ISSUER_PRIVATE_KEY_JWK;
    const issuerCertificate = ISSUER_CERTIFICATE;
    const document = await new Document('org.iso.18013.5.1.mDL')
      .addIssuerNameSpace('org.iso.18013.5.1', {
        family_name: 'Jones',
        given_name: 'Ava',
        birth_date: '2007-03-25',
      })
      .useDigestAlgorithm('SHA-256')
      .addValidityInfo({
        signed: new Date(),
      })
      .addDeviceKeyInfo({ deviceKey: DEVICE_JWK })
      .sign({
        issuerPrivateKey,
        issuerCertificate,
        alg: 'ES256',
      });
    issuerMDoc = new MDoc([document]).encode();
    console.log('[*] Issuing a credential:');
    console.log(inspect(issuerMDoc), {showHidden: false, depth: null, colors: true});
    const decodedCredential = cbor.decodeAllSync(issuerMDoc);
    console.log('[*] CBOR decoded credential:');
    console.log(inspect(decodedCredential, {showHidden: false, depth: null, colors: true}));
    console.log('[*] CBOR decoded credential (IssuerAuth):');
    const issuerAuth = decodedCredential[0].documents[0].issuerSigned.issuerAuth;
    console.log(inspect(issuerAuth, {showHidden: false, depth: null, colors: true}));
  }

  // This is what the DEVICE does to generate a response:
  {
    const mdocGeneratedNonce = '123456';
    const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4';
    const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df-d6ea-4c84-9985-37a8b81a82ec/callback';
    const verifierGeneratedNonce = 'abcdefg';
    const PRESENTATION_DEFINITION_1 = {
      id: 'mdl-test-all-data',
      input_descriptors: [
        {
          id: 'org.iso.18013.5.1.mDL',
          format: {
            mso_mdoc: {
              alg: ['EdDSA', 'ES256'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ["$['org.iso.18013.5.1']['family_name']"],
                intent_to_retain: false,
              },
            ],
          },
        },
      ],
    };

    deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
      .usingPresentationDefinition(PRESENTATION_DEFINITION_1)
      .usingHandover([mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce])
      .authenticateWithSignature(DEVICE_JWK, 'ES256')
      .sign();

    console.log('[*] Generating a device response:');
    console.log(inspect(deviceResponseMDoc), {showHidden: false, depth: null, colors: true});
    console.log('[*] Generating a device response (DeviceSignedDocument):');
    console.log(inspect(deviceResponseMDoc.documents[0]), {showHidden: false, depth: null, colors: true});
  }
})();