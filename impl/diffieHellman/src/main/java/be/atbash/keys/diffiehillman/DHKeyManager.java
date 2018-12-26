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
package be.atbash.keys.diffiehillman;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.generator.DHGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.crypto.spec.DHParameterSpec;
import javax.enterprise.inject.Vetoed;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Vetoed
public class DHKeyManager implements KeyManager {

    private static final Object LOCK = new Object();
    private static DHKeyManager INSTANCE;

    private KeyGenerator keyGenerator;
    private Map<String, List<AtbashKey>> keys;

    private void init() {
        keys = new HashMap<>();
        keyGenerator = new KeyGenerator();
    }

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }

        List<KeyFilter> filters = selectorCriteria.asKeyFilters();

        List<AtbashKey> result = new ArrayList<>();
        // TODO Should we restrict this to a tenantId?
        for (Map.Entry<String, List<AtbashKey>> entry : keys.entrySet()) {
            result.addAll(entry.getValue());
        }
        for (KeyFilter filter : filters) {
            result = filter.filter(result);
        }

        return result;

    }

    public void createKeyPair(String tenantId, String kid) {
        createKeyPair(tenantId, kid, null);
    }

    public void createKeyPair(String tenantId, String kid, DHParameterSpec parameterSpec) {
        DHGenerationParameters.DHGenerationParametersBuilder parameterBuilder = new DHGenerationParameters.DHGenerationParametersBuilder()
                .withKeyId(kid);

        if (parameterSpec == null) {
            parameterBuilder.withKeySize(1024);
        } else {
            parameterBuilder.withDHParamaterSpec(parameterSpec);
        }
        List<AtbashKey> atbashKeys = getKeysForTenantId(tenantId);
        atbashKeys.addAll(keyGenerator.generateKeys(parameterBuilder.build()));

    }

    public static DHKeyManager getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new DHKeyManager();
                    INSTANCE.init();
                }
            }
        }
        return INSTANCE;
    }

    public void storePublicKey(String tenantId, AtbashKey publicKey) {
        List<AtbashKey> atbashKeys = getKeysForTenantId(tenantId);

        // See if key already stored (on the safe side and normally not needed unless when testing within 1 JVM
        boolean found = false;
        for (AtbashKey atbashKey : atbashKeys) {
            if (publicKey.getKeyId().equals(atbashKey.getKeyId())) {
                found = true;
            }
        }
        if (!found) {
            atbashKeys.add(publicKey);
        }
    }

    private List<AtbashKey> getKeysForTenantId(String tenantId) {
        List<AtbashKey> atbashKeys = keys.get(tenantId);
        if (atbashKeys == null) {
            atbashKeys = new ArrayList<>();
            keys.put(tenantId, atbashKeys);
        }
        return atbashKeys;
    }
}
