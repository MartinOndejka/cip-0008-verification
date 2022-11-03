package org.MartinOndejka;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Map;

public class COSE_Key {
    public static final String PUBLIC_KEY_ID = "-2";

    private final CBORMapper mapper;

    public final Map<String, Object> map;

    COSE_Key(String hexData) throws IOException {
        this(Hex.decode(hexData));
    }

    COSE_Key(byte[] data) throws IOException {
        this.mapper = new CBORMapper();

        this.map = mapper.readValue(data, Map.class);
    }

    public byte[] getPublicKey() {
        return (byte[]) map.get(PUBLIC_KEY_ID);
    }
}
