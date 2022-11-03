package org.MartinOndejka;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        String hexSignature = "845846a201276761646472657373583900eeb15a1bf1e1f42481e6d1978187b7a29122bcffb0f0bb96a68c6746b5a38076729b8fc0e1e77f5fb23e2e59d974a50279a9b0451c1ce2dfa166686173686564f444ff0102035840a37db2cbdb23ef2b1e6d67d56d31afd73d246521081baed8b55302dfe843c2c97a1a18f7c311890ebd662c3bde6ae99722db4927fe94ba20746cf25730311d0b";
        String hexKey = "a4010103272006215820367b125ce4df0b28a06b8dd66155c09a5137e8aa9b7686b77ded56675b084479";

        COSE_Sign1 signature = new COSE_Sign1(hexSignature);
        COSE_Key cose_key = new COSE_Key(hexKey);

        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(cose_key.getPublicKey(), 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, publicKey);

        byte[] sigStructure = signature.getSigStructure();
        signer.update(sigStructure, 0, sigStructure.length);

        System.out.println(signer.verifySignature(signature.getSignature()));
    }
}