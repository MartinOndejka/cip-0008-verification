package org.MartinOndejka;

import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressService;
import com.bloxbean.cardano.client.cip.cip8.COSEKey;
import com.bloxbean.cardano.client.cip.cip8.COSESign1;
import com.bloxbean.cardano.client.crypto.api.impl.EdDSASigningProvider;
import com.bloxbean.cardano.client.util.HexUtil;

public class Main {
    public static void main(String[] args) {
        String hexSignature = "845846a201276761646472657373583900eeb15a1bf1e1f42481e6d1978187b7a29122bcffb0f0bb96a68c6746b5a38076729b8fc0e1e77f5fb23e2e59d974a50279a9b0451c1ce2dfa166686173686564f444ff0102035840a37db2cbdb23ef2b1e6d67d56d31afd73d246521081baed8b55302dfe843c2c97a1a18f7c311890ebd662c3bde6ae99722db4927fe94ba20746cf25730311d0b";
        String hexKey = "a4010103272006215820367b125ce4df0b28a06b8dd66155c09a5137e8aa9b7686b77ded56675b084479";

        COSESign1 sign1 = COSESign1.deserialize(HexUtil.decodeHexString(hexSignature));
        COSEKey key = COSEKey.deserialize(HexUtil.decodeHexString(hexKey));

        Address address = new Address(sign1.headers()._protected().getAsHeaderMap().otherHeaderAsBytes("address"));

        EdDSASigningProvider signer = new EdDSASigningProvider();

        boolean verified = signer.verify(
                sign1.signature(),
                sign1.signedData().serializeAsBytes(),
                key.otherHeaderAsBytes(-2)
        ) && AddressService.getInstance().verifyAddress(address, key.otherHeaderAsBytes(-2));

        System.out.println(verified);
    }
}