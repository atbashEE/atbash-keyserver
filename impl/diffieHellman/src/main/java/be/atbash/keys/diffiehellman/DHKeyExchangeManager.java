/*
 * Copyright 2018 Rudy De Busscher
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.keys.diffiehellman;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.annotation.PostConstruct;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@ApplicationScoped
public class DHKeyExchangeManager {

    private static DHKeyExchangeManager INSTANCE;

    private DHKeyManager dhKeyManager;
    private DHKeySelector dhKeySelector;  // FIXME Why not injection

    private Map<String, List<String>> exchangeIdsForTenant;

    @PostConstruct
    public void init() {
        dhKeyManager = DHKeyManager.getInstance();
        dhKeySelector = new DHKeySelector();
        exchangeIdsForTenant = new HashMap<>();
    }

    /**
     * Generates an exchangeId and DH key pair.
     *
     * @return public data from Alice.
     */
    public AlicePublicData startExchange(String tenantId) {
        String exchangeID = UUID.randomUUID().toString();
        String kid = "alice-" + exchangeID;

        dhKeyManager.createKeyPair(tenantId, kid);

        AtbashKey atbashKey = getPublicKey(kid);

        AlicePublicData result = new AlicePublicData();
        result.setTenantId(tenantId);
        result.setPublicKey(atbashKey);
        result.setDhParameterSpec(((DHPublicKey) atbashKey.getKey()).getParams());

        return result;
    }

    private void storeExchangeId(String tenantId, String exchangeId) {
        List<String> ids = exchangeIdsForTenant.get(tenantId);
        if (ids == null) {
            ids = new ArrayList<>();
            exchangeIdsForTenant.put(tenantId, ids);
        }
        ids.add(exchangeId);
    }

    private AtbashKey getPublicKey(String kid) {
        SelectorCriteria criteria = SelectorCriteria.newBuilder()
                .withId(kid)
                .withAsymmetricPart(AsymmetricPart.PUBLIC)
                .build();

        return dhKeySelector.selectAtbashKey(criteria);
    }

    /**
     * Bob receives the public key from Alice and return his public key.
     *
     * @param publicData Public Key data info from Alice
     * @return Public Key info from Bob.
     */
    public BobPublicData acknowledgeExchange(AlicePublicData publicData) {
        dhKeyManager.storePublicKey(publicData.getTenantId(), publicData.getPublicKey());
        storeExchangeId(publicData.getTenantId(), publicData.getPublicKey().getKeyId());

        String kid = publicData.getPublicKey().getKeyId().replaceAll("alice-", "bob-");
        dhKeyManager.createKeyPair(publicData.getTenantId(), kid);

        AtbashKey atbashKey = getPublicKey(kid);

        BobPublicData result = new BobPublicData();
        result.setTenantId(publicData.getTenantId());
        result.setPublicKey(atbashKey);

        return result;
    }

    /**
     * Creates the shared SecretKey based on the public Key from the other party using the Private Key
     * from ourself.
     *
     * @param publicKey Public key from other party
     * @return The shared SecretKey
     */
    public SecretKey defineSecretKey(AtbashKey publicKey) {
        String privateKeyId = definePrivateKeyId(publicKey.getKeyId());
        AtbashKey privateKey = getPrivateKey(privateKeyId);

        try {
            // Step 4 part 1:  Alice/Bob performs the first phase of the
            //		protocol with her/his private key
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privateKey.getKey());

            // Step 4 part 2:  Alice/Bob performs the second phase of the
            //		protocol with Bob's/Alice's public key
            ka.doPhase(publicKey.getKey(), true);

            // Step 4 part 3:  Alice/Bob can generate the secret key
            byte[] secret = ka.generateSecret();

            // Step 6:  Alice/Bob generates a AES key
            char[] chars = new char[secret.length];
            for (int i = 0; i < secret.length; i++) {
                chars[i] = (char) secret[i];
            }

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] secretBytes = keyFactory.generateSecret(
                    new PBEKeySpec(chars, secret, 1014, 16 * 8)).getEncoded();

            return new SecretKeySpec(secretBytes, "AES");
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            throw new AtbashUnexpectedException(e);
        }

    }

    public SecretKey defineSecretKey(String exchangeId) {
        AtbashKey publicKey = retrieveKeyPublicKey(exchangeId);

        return defineSecretKey(publicKey);
    }

    private AtbashKey retrieveKeyPublicKey(String exchangeId) {

        SelectorCriteria criteria = SelectorCriteria.newBuilder()
                .withId(exchangeId)
                .withAsymmetricPart(AsymmetricPart.PUBLIC)
                .build();
        return dhKeySelector.selectAtbashKey(criteria);
    }

    private AtbashKey getPrivateKey(String kid) {
        SelectorCriteria criteria = SelectorCriteria.newBuilder()
                .withId(kid)
                .withAsymmetricPart(AsymmetricPart.PRIVATE)
                .build();

        return dhKeySelector.selectAtbashKey(criteria);
    }


    private String definePrivateKeyId(String keyId) {
        if (keyId.startsWith("alice-")) {
            return keyId.replaceAll("alice-", "bob-");
        }
        if (keyId.startsWith("bob-")) {
            return keyId.replaceAll("bob-", "alice-");
        }
        throw new AtbashUnexpectedException(String.format("Unrecognized key Id structure '%s'", keyId));
    }

    public String getTenantId(String exchangeId) {
        String result = null;
        for (Map.Entry<String, List<String>> entry : exchangeIdsForTenant.entrySet()) {
            for (String id : entry.getValue()) {
                if (id.equals(exchangeId)) {
                    result = entry.getKey();
                }
            }
        }
        return result;
    }

    public void removeKeys(String tenantId, String exchangeId) {
        String keyId;
        if (exchangeId.startsWith("alice")) {
            keyId = exchangeId.substring(5);
        } else {
            // starts with bob
            keyId = exchangeId.substring(3);
        }

        SelectorCriteria selectorCriteria = SelectorCriteria.newBuilder().withId(keyId).build();
        dhKeyManager.removeKeys(tenantId, selectorCriteria);
    }

    public static synchronized DHKeyExchangeManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new DHKeyExchangeManager();
            INSTANCE.init();
        }
        return INSTANCE;
    }


}
