====
    Copyright 2018-2020 Rudy De Busscher

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
====

    /**
     * Derives a shared secret (also called 'Z') from the specified ECDH
     * key agreement.
     *
     * @param publicKey  The public OKP key, i.e. the consumer's public EC
     *                   key on encryption, or the ephemeral public EC key
     *                   on decryption. Must not be {@code null}.
     * @param privateKey The private OKP key, i.e. the ephemeral private EC
     *                   key on encryption, or the consumer's private EC
     *                   key on decryption. Must not be {@code null}.
     * @return The derived shared secret ('Z'), with algorithm "AES".
     * @throws JOSEException If derivation of the shared secret failed.
     */
    // FIXME How do we use this? And if not, can be removed
    public static SecretKey deriveSharedSecret(OctetKeyPair publicKey, OctetKeyPair privateKey)
            throws JOSEException {

        if (publicKey.isPrivate()) {
            throw new JOSEException("Expected public key but received OKP with 'd' value");
        }

        if (!Curve.X25519.equals(publicKey.getCurve())) {
            throw new JOSEException("Expected public key OKP with crv=X25519");
        }

        if (!privateKey.isPrivate()) {
            throw new JOSEException("Expected private key but received OKP without 'd' value");
        }

        if (!Curve.X25519.equals(privateKey.getCurve())) {
            throw new JOSEException("Expected private key OKP with crv=X25519");
        }

        byte[] privateKeyBytes = privateKey.getDecodedD();
        byte[] publicKeyBytes = publicKey.getDecodedX();

        byte[] sharedSecretBytes;
        //try {
        throw new UnsupportedOperationException("Import from Google Crypto ");  // FIXME
        //sharedSecretBytes = X25519.computeSharedSecret(privateKeyBytes, publicKeyBytes);
        //} catch (InvalidKeyException e) {
        //    throw new JOSEException(e.getMessage(), e);
        //}

        //return new SecretKeySpec(sharedSecretBytes, "AES");
    }
