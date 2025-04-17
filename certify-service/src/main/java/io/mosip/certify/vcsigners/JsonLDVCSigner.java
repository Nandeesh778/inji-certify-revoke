/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.vcsigners;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

/**
 * JsonLDVCSigner is a VCSigner which uses the Certify embedded
 * keymanager to perform VC signing tasks for JSON LD VCs.
 * These are the known external requirements:
 * - the public key must be pre-hosted for the VC & should be available
 *    so long that VC should be verifiable
 * - the VC should have a validFrom or issuanceDate in a specific UTC format,
 *  if missing it uses current time for proof creation timestamp.
 */
@Slf4j
@Service
public class JsonLDVCSigner implements VCSigner {

    @Autowired
    ProofGenerator proofGenerator;
    @Value("${mosip.certify.data-provider-plugin.issuer-public-key-uri}")
    private String issuerPublicKeyURI;

    @Override
    public VCResult<JsonLDObject> attachSignature(String unSignedVC, Map<String, String> keyReferenceDetails) {
        System.out.println("Starting signature attachment process");

        VCResult<JsonLDObject> VC = new VCResult<>();
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(unSignedVC);
        jsonLDObject.setDocumentLoader(null);
        System.out.println("Parsed unsigned VC into JsonLDObject");

        String validFrom;
        if (jsonLDObject.getJsonObject().containsKey(VCDM1Constants.ISSUANCE_DATE)) {
            validFrom = jsonLDObject.getJsonObject().get(VCDM1Constants.ISSUANCE_DATE).toString();
            System.out.println("ValidFrom found in ISSUANCE_DATE: " + validFrom);
        } else if (jsonLDObject.getJsonObject().containsKey(VCDM2Constants.VALID_FROM)) {
            validFrom = jsonLDObject.getJsonObject().get(VCDM2Constants.VALID_FROM).toString();
            System.out.println("ValidFrom found in VALID_FROM: " + validFrom);
        } else {
            validFrom = ZonedDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            System.out.println("ValidFrom not found, using current time: " + validFrom);
        }

        Date createDate = Date
                .from(LocalDateTime
                        .parse(validFrom, DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN))
                        .atZone(ZoneId.systemDefault()).toInstant());

        LdProof vcLdProof = LdProof.builder()
                .defaultContexts(false)
                .defaultTypes(false)
                .type(proofGenerator.getName())
                .created(createDate)
                .proofPurpose(VCDMConstants.ASSERTION_METHOD)
                .verificationMethod(URI.create(issuerPublicKeyURI))
                .build();
        System.out.println("LdProof created with type: " + proofGenerator.getName() + " and verification method: " + issuerPublicKeyURI);

        Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
        byte[] vcHashBytes;
        try {
            vcHashBytes = canonicalizer.canonicalize(vcLdProof, jsonLDObject);
            System.out.println("Canonicalization successful. Canonicalized hash length: " + vcHashBytes.length);
        } catch (IOException | GeneralSecurityException | JsonLDException e) {
            System.out.println("Error during canonicalization: " + e.getMessage());
            throw new CertifyException("Error during canonicalization");
        }

        String vcEncodedHash = Base64.getUrlEncoder().encodeToString(vcHashBytes);
        System.out.println("Base64 encoded canonicalized hash: " + vcEncodedHash);

        LdProof ldProofWithJWS = proofGenerator.generateProof(vcLdProof, vcEncodedHash, keyReferenceDetails);
        System.out.println("Proof generated with JWS");

        ldProofWithJWS.addToJsonLDObject(jsonLDObject);
        System.out.println("Proof added to JsonLDObject");

        VC.setCredential(jsonLDObject);
        System.out.println("Signature successfully attached to VC");

        return VC;
    }

}
