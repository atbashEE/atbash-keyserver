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
import be.atbash.util.TestReflectionUtils;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

public class DHKeyExchangeManagerTest {

    private DHKeyExchangeManager exchangeManager1 = DHKeyExchangeManager.getInstance();
    private DHKeyExchangeManager exchangeManager2 = DHKeyExchangeManager.getInstance();

    @Before
    public void setup() throws NoSuchFieldException {
        // Since this is a singleton, we need to clear it before it each test
        DHKeyManager keyManager = DHKeyManager.getInstance();
        Map<String, List<AtbashKey>> keys = TestReflectionUtils.getValueOf(keyManager, "keys");
        keys.clear();
    }

    @Test
    public void defineSecretKey() {
        AlicePublicData alicePublicData = exchangeManager1.startExchange("JUnit");

        BobPublicData bobPublicData = exchangeManager2.acknowledgeExchange(alicePublicData);

        SecretKey secretKey1 = exchangeManager1.defineSecretKey(bobPublicData.getPublicKey());
        SecretKey secretKey2 = exchangeManager2.defineSecretKey(alicePublicData.getPublicKey().getKeyId());

        assertThat(secretKey1.getEncoded()).isEqualTo(secretKey2.getEncoded());
    }

    @Test
    public void checkKeys() throws NoSuchFieldException {
        AlicePublicData alicePublicData = exchangeManager1.startExchange("JUnit");

        BobPublicData bobPublicData = exchangeManager2.acknowledgeExchange(alicePublicData);

        exchangeManager1.defineSecretKey(bobPublicData.getPublicKey());
        exchangeManager2.defineSecretKey(alicePublicData.getPublicKey().getKeyId());

        // Since DHKeyManager is a singleton, both DHKeyManager point to the same DHKeyManager
        DHKeyManager keyManager = DHKeyManager.getInstance();
        Map<String, List<AtbashKey>> keys = TestReflectionUtils.getValueOf(keyManager, "keys");
        assertThat(keys).containsOnlyKeys("JUnit");
        assertThat(keys.get("JUnit")).hasSize(4);

        // Assemble data about keys
        Set<String> keysIds = new HashSet<>();
        Map<String, Integer> keyTypes = new HashMap<>();
        Map<AsymmetricPart, Integer> asymmetricParts = new EnumMap<>(AsymmetricPart.class);

        for (AtbashKey atbashKey : keys.get("JUnit")) {
            keysIds.add(atbashKey.getKeyId());

            String keyType = atbashKey.getSecretKeyType().getKeyType().getValue();
            Integer cnt = keyTypes.get(keyType);
            if (cnt == null) {
                cnt = 0;
            }
            cnt++;
            keyTypes.put(keyType, cnt);

            AsymmetricPart asymmetricPart = atbashKey.getSecretKeyType().getAsymmetricPart();
            cnt = asymmetricParts.get(asymmetricPart);
            if (cnt == null) {
                cnt = 0;
            }
            cnt++;
            asymmetricParts.put(asymmetricPart, cnt);
        }

        assertThat(keysIds).hasSize(2);
        Iterator<String> iterator = keysIds.iterator();
        String keyId1 = iterator.next();
        String keyId2 = iterator.next();
        assertThat(stripKeyId(keyId1)).isEqualTo(stripKeyId(keyId2));

        assertThat(keyTypes).containsOnlyKeys("DH");
        assertThat(keyTypes.get("DH")).isEqualTo(4);

        assertThat(asymmetricParts).containsOnlyKeys(AsymmetricPart.PRIVATE, AsymmetricPart.PUBLIC);
        assertThat(asymmetricParts.get(AsymmetricPart.PRIVATE)).isEqualTo(2);
        assertThat(asymmetricParts.get(AsymmetricPart.PUBLIC)).isEqualTo(2);
    }

    private String stripKeyId(String keyId) {
        String result = null;
        if (keyId.startsWith("bob")) {
            result = keyId.substring(3);
        }
        if (keyId.startsWith("alice")) {
            result = keyId.substring(5);
        }
        return result;
    }


    @Test
    public void removeKeys() throws NoSuchFieldException {
        AlicePublicData alicePublicData = exchangeManager1.startExchange("JUnit");

        BobPublicData bobPublicData = exchangeManager2.acknowledgeExchange(alicePublicData);

        exchangeManager1.defineSecretKey(bobPublicData.getPublicKey());
        exchangeManager2.defineSecretKey(alicePublicData.getPublicKey().getKeyId());

        exchangeManager1.removeKeys("JUnit", alicePublicData.getPublicKey().getKeyId());

        // Since DHKeyManager is a singleton, both DHKeyManager point to the same DHKeyManager
        DHKeyManager keyManager = DHKeyManager.getInstance();
        Map<String, List<AtbashKey>> keys = TestReflectionUtils.getValueOf(keyManager, "keys");
        assertThat(keys.keySet().isEmpty()).isTrue();
    }
}