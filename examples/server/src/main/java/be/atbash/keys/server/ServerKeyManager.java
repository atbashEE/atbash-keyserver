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
package be.atbash.keys.server;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.exception.AtbashIllegalActionException;

import javax.enterprise.inject.Vetoed;
import java.util.*;

@Vetoed // Otherwise clashes with some other KeyManager implementations? TODO Sort this out
public class ServerKeyManager implements KeyManager {

    private static final Object LOCK = new Object();
    private static ServerKeyManager INSTANCE;

    private Map<String, List<AtbashKey>> keys;

    private ServerKeyManager() {
        keys = new HashMap<>();
    }

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }
        if (selectorCriteria.getDiscriminator() == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria.discriminator can't be null");
        }

        String tenantId = selectorCriteria.getDiscriminator().toString();
        List<KeyFilter> filters = selectorCriteria.asKeyFilters();

        List<AtbashKey> result = new ArrayList<>(keys.get(tenantId));
        for (KeyFilter filter : filters) {
            result = filter.filter(result);
        }

        return result;
    }

    public String generateKeys(String tenantId) {

        // Define which type of keys are generated and send over.
        String kid = UUID.randomUUID().toString();
        List<AtbashKey> atbashKeys = keys.get(tenantId);
        if (atbashKeys == null) {
            atbashKeys = new ArrayList<>();
            keys.put(tenantId, atbashKeys);
        }
        atbashKeys.addAll(generateRSAKeys(kid));
        return kid;
    }

    private List<AtbashKey> generateRSAKeys(String kid) {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(kid)
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    public static ServerKeyManager getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new ServerKeyManager();
                }
            }
        }
        return INSTANCE;
    }

}
