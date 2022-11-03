package org.MartinOndejka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class COSE_Sign1 {
    public static final String ADDRESS_LABEL = "address";

    private final CBORMapper mapper;

    private final byte[] protectedHeaders;
    private final Map<String, Object> unprotectedHeaders;
    private final byte[] payload;
    private final byte[] signature;

    COSE_Sign1(String hexData) throws IOException {
        this(Hex.decode(hexData));
    }

    COSE_Sign1(byte[] data) throws IOException {
        this.mapper = new CBORMapper();

        List<Object> topArray = mapper.readValue(data, List.class);

        this.protectedHeaders = (byte[]) topArray.get(0);
        this.unprotectedHeaders = (Map) topArray.get(1);
        this.payload = (byte[]) topArray.get(2);
        this.signature = (byte[]) topArray.get(3);
    }

    public byte[] getSigStructure() throws JsonProcessingException {
        return getSigStructure(new byte[0]);
    }

    public byte[] getSigStructure(byte[] external_aad) throws JsonProcessingException {
        List<Object> sigStructure = new ArrayList<>();

        sigStructure.add("Signature1");
        sigStructure.add(protectedHeaders);
        sigStructure.add(external_aad);
        sigStructure.add(payload);

        return mapper.writeValueAsBytes(sigStructure);
    }

    public Map getProtectedHeaders() throws IOException {
        return mapper.readValue(this.protectedHeaders, Map.class);
    }

    public byte[] getAddress() throws IOException {
        return (byte[]) getProtectedHeaders().get(ADDRESS_LABEL);
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public byte[] getSignature() {
        return this.signature;
    }
}
