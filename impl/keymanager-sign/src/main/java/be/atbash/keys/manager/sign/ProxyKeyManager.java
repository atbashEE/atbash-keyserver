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
package be.atbash.keys.manager.sign;


import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.keys.selector.filter.KeyFilter;
import be.atbash.util.exception.AtbashIllegalActionException;

import java.util.ArrayList;
import java.util.List;

public class ProxyKeyManager implements KeyManager {

    private static final Object LOCK = new Object();

    private TTLBag<AtbashKey> keys;

    private KeyRequester keyRequester = new KeyRequester();

    @Override
    public List<AtbashKey> retrieveKeys(SelectorCriteria selectorCriteria) {
        if (selectorCriteria == null) {
            throw new AtbashIllegalActionException("Parameter selectorCriteria can't be null");
        }

        List<KeyFilter> filters = selectorCriteria.asKeyFilters();

        if (filters.size() == 1 && filters.get(0) instanceof AsymmetricPartKeyFilter) {
            return getKeys();
        }

        return new ArrayList<>();
    }

    private List<AtbashKey> getKeys() {
        initialize();
        List<AtbashKey> result = keys.currentItems();
        if (result.isEmpty()) {
            result.add(keyRequester.requestKeyFromServer());
        }

        return result;
    }

    private void initialize() {
        if (keys == null) {
            synchronized (LOCK) {
                if (keys == null) {
                    keys = new TTLBag<>(600000);  // FIXME Config
                }
            }
        }
    }
}
