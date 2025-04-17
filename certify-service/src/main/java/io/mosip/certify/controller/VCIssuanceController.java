/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.exception.InvalidNonceException;
import io.mosip.certify.services.BitStringStatusListService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.Locale;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/issuance")
public class VCIssuanceController {

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    private BitStringStatusListService bitStringStatusListService;

    @Autowired
    MessageSource messageSource;

    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/credential",produces = "application/json")
    public CredentialResponse getCredential(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        return vcIssuanceService.getCredential(credentialRequest);
    }

    @GetMapping("/credential/status/{id}")
    public ResponseEntity<Map<String, Object>> verifyCredentialStatus(
            @PathVariable("id") String statusListCredentialId,
            @RequestParam("statusListIndex") long statusListIndex,
            @RequestParam("statusPurpose") String statusPurpose) {
        try {
            String statusListCredentialUrl = "https://bdf0-223-185-133-199.ngrok-free.app/v1/certify/issuance/credential/status/" + statusListCredentialId;
            boolean isValid = bitStringStatusListService.validateCredentialStatus(statusListCredentialUrl, statusListIndex, statusPurpose);
            System.out.println("isValid>>>>>>>>>>>>>" + isValid);
            return ResponseEntity.ok(Map.of(
                    "status", isValid ? "valid" : "revoked",
                    "statusListCredentialUrl", statusListCredentialUrl,
                    "statusListIndex", statusListIndex
            ));
        } catch (Exception e) {
            log.error("Error verifying credential status", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/credential/revoke")
    public ResponseEntity<?> revokeCredential(
            @RequestParam("statusListCredentialUrl") String statusListCredentialUrl,
            @RequestParam("statusListIndex") long statusListIndex,
            @RequestParam("statusPurpose") String statusPurpose
    ) {
        try {
            bitStringStatusListService.revokeCredential(
                statusListCredentialUrl,
                statusListIndex,
                statusPurpose
            );
            return ResponseEntity.ok(Map.of("message", "Credential revoked successfully"));
        } catch (Exception e) {
            log.error("Error revoking credential", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
        }
    }




    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/vd12/credential",produces = "application/json")
    public CredentialResponse getCredentialV12Draft(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        CredentialResponse credentialResponse = vcIssuanceService.getCredential(credentialRequest);
        credentialResponse.setFormat(credentialRequest.getFormat());
        return credentialResponse;
    }


    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/vd11/credential",produces = "application/json")
    public CredentialResponse getCredentialV11Draft(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        CredentialResponse credentialResponse = vcIssuanceService.getCredential(credentialRequest);
        credentialResponse.setFormat(credentialRequest.getFormat());
        return credentialResponse;
    }
    /**
     * Open endpoint to provide VC issuer's metadata
     * @return
     */
    @GetMapping(value = "/.well-known/openid-credential-issuer",produces = "application/json")
    public Map<String, Object> getMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return vcIssuanceService.getCredentialIssuerMetadata(version);
    }

    @GetMapping(value = "/.well-known/did.json")
    public Map<String, Object> getDIDDocument() {
       return vcIssuanceService.getDIDDocument();
    }


    @ResponseBody
    @ExceptionHandler(InvalidNonceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public VCError invalidNonceExceptionHandler(InvalidNonceException ex) {
        VCError vcError = new VCError();
        vcError.setError(ex.getErrorCode());
        vcError.setError_description(messageSource.getMessage(ex.getErrorCode(), null, ex.getErrorCode(), Locale.getDefault()));
        vcError.setC_nonce(ex.getClientNonce());
        vcError.setC_nonce_expires_in(ex.getClientNonceExpireSeconds());
        return vcError;
    }
}
