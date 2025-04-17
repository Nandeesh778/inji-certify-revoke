package io.mosip.certify.services;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.LedgerIssuanceTable;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.repository.LedgerIssuanceTableRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Map;
import org.json.JSONObject;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.vcsigners.VCSigner;

@Slf4j
@Service
public class BitStringStatusListService {

    private static final int MINIMUM_BITSTRING_SIZE = 131072; // 16 KB
    private static final int STATUS_SIZE = 1; // Default status size as per spec

    @Autowired
    private VCSigner vcSigner;

    @Value("${mosip.certify.data-provider-plugin.issuer-uri}")
    private String issuerURI;

    @Autowired
    private StatusListCredentialRepository statusListCredentialRepository;

    @Autowired
    private LedgerIssuanceTableRepository ledgerIssuanceTableRepository;

    /**
     * Generate Status List Credential as per Section 3.3 Bitstring Generation Algorithm
     *
     * @param issuerId Issuer identifier
     * @param statusPurpose Purpose of the status list (e.g., "revocation")
     * @return URL of the generated status list credential
     */
    public String generateStatusListCredential(String issuerId, String statusPurpose, String domainUrl) {
        Optional<StatusListCredential> existingList = statusListCredentialRepository.findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);
        System.out.println("Existing issuerId  found: " + issuerId);
        System.out.println("Existing statusPurpose found: " + statusPurpose);
        System.out.println("Existing status list found: " + existingList);
        if (existingList.isPresent()) {
            return existingList.get().getId();
        }
        
        byte[] bitstring = new byte[MINIMUM_BITSTRING_SIZE];
        System.out.println("Bitstring size: " + bitstring.length);
        List<LedgerIssuanceTable> issuedCredentials = ledgerIssuanceTableRepository.findByIssuerIdAndStatusPurpose(issuerId, statusPurpose);
        System.out.println("Issued credentials found: " + issuedCredentials +"hello"+ issuedCredentials.size());

        
        for (LedgerIssuanceTable credential : issuedCredentials) {
            int index = (int) (credential.getStatusListIndex() * STATUS_SIZE);
            String status = credential.getCredentialStatus();
            System.out.println("Credential index: " + index + ", status: " + status);
            if (index < bitstring.length) {
                bitstring[index] = credential.getCredentialStatus().equals("revoked") ? (byte) 1 : (byte) 0;
                System.out.println("bitstring[" + index + "] = " + bitstring[index] +"-------"+ bitstring);
            }
            else {
                System.out.println("WARNING: Index " + index + " is out of bounds for bitstring of size " + bitstring.length);
            }
        }

        // Insert here to print raw bitstring before compression
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) { // print first 100 bits for inspection
            sb.append(bitstring[i]);
        }
        System.out.println("Raw Bitstring: " + sb.toString());
        System.out.println("Bitstring <<<<<<<<<<<<<<: " + bitstring);

        String compressedBitstring = compressAndEncodeBitstring(bitstring);
        System.out.println("Compressed Bitstring: " + compressedBitstring);
        String statusListId = domainUrl + "/credential/status/" + "123";
        StatusListCredential statusList = new StatusListCredential();
        statusList.setId(statusListId);
        statusList.setIssuerId(issuerId);
        statusList.setStatusPurpose(statusPurpose);
        statusList.setEncodedList(compressedBitstring);
        statusList.setListSize(issuedCredentials.size());
        statusList.setValidFrom(LocalDateTime.now());

        statusListCredentialRepository.save(statusList);

        return statusListId;
    }

    public boolean validateCredentialStatus(String statusListCredentialUrl, long statusListIndex, String statusPurpose) {
        Optional<StatusListCredential> statusListOptional = statusListCredentialRepository.findById(statusListCredentialUrl);
        if (statusListOptional.isEmpty()) {
            log.error("Status List Credential not found: {}", statusListCredentialUrl);
            throw new RuntimeException("Status List Credential not found");
        }

        StatusListCredential statusList = statusListOptional.get();
        if (!statusPurpose.equals(statusList.getStatusPurpose())) {
            log.error("Status Purpose Mismatch: expected={}, found={}", statusPurpose, statusList.getStatusPurpose());
            throw new RuntimeException("Status Purpose Mismatch");
        }

        byte[] uncompressedBitstring = decompressAndDecodeBitstring(statusList.getEncodedList());
        System.out.println("Uncompressed Bitstring: " + uncompressedBitstring.length);
        if (uncompressedBitstring.length / STATUS_SIZE < MINIMUM_BITSTRING_SIZE) {
            log.error("Status List Length Too Short: expected={}, found={}", MINIMUM_BITSTRING_SIZE, uncompressedBitstring.length / STATUS_SIZE);
            throw new RuntimeException("Status List Length Too Short");
        }

        // Check credential status
        int index = (int) (statusListIndex * STATUS_SIZE);
        if (index >= uncompressedBitstring.length) {
            log.error("Status List Index Out of Range: index={}, maxIndex={}", index, uncompressedBitstring.length - 1);
            throw new RuntimeException("Status List Index Out of Range");
        }

        // Return true if bit is 0 (valid), false if bit is 1 (revoked/invalid)
        return uncompressedBitstring[index] == 0;
    }

    /**
     * Compress bitstring using GZIP and encode using Base64url
     *
     * @param bitstring Uncompressed bitstring
     * @return Compressed and Base64url encoded bitstring
     */
    private String compressAndEncodeBitstring(byte[] bitstring) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzipOS = new GZIPOutputStream(baos)) {
            gzipOS.write(bitstring);
            gzipOS.close();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            log.error("Error compressing bitstring", e);
            throw new RuntimeException("Bitstring Compression Failed", e);
        }
    }

    /**
     * Decompress bitstring from Base64url and GZIP
     *
     * @param compressedBitstring Compressed and Base64url encoded bitstring
     * @return Uncompressed bitstring
     */
    private byte[] decompressAndDecodeBitstring(String compressedBitstring) {
        try {
            byte[] compressedBytes = Base64.getUrlDecoder().decode(compressedBitstring);
            try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedBytes);
                 GZIPInputStream gzipIS = new GZIPInputStream(bais);
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = gzipIS.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                return baos.toByteArray();
            }
        } catch (IOException e) {
            log.error("Error decompressing bitstring", e);
            throw new RuntimeException("Bitstring Decompression Failed", e);
        }
    }

    public void revokeCredential(String statusListCredentialUrl, long statusListIndex, String statusPurpose) {
        Optional<StatusListCredential> statusListOptional = statusListCredentialRepository.findById(statusListCredentialUrl);
        System.out.println("Status List Credential found: " + statusListOptional);
        if (statusListOptional.isEmpty()) {
            throw new RuntimeException("Status List Credential not found");
        }
    
        StatusListCredential statusList = statusListOptional.get();
        if (!statusPurpose.equals(statusList.getStatusPurpose())) {
            throw new RuntimeException("Status Purpose mismatch");
        }
    
        byte[] bitstring = decompressAndDecodeBitstring(statusList.getEncodedList());
        int index = (int) (statusListIndex * STATUS_SIZE);
    
        if (index >= bitstring.length) {
            throw new RuntimeException("Status List Index Out of Range");
        }
    
        bitstring[index] = 1; // Mark as revoked
        String updatedEncodedList = compressAndEncodeBitstring(bitstring);
        statusList.setEncodedList(updatedEncodedList);
        statusList.setValidFrom(LocalDateTime.now());
    
        statusListCredentialRepository.save(statusList);
    }
    
}
