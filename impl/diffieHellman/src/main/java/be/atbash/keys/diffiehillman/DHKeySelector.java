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

import be.atbash.ee.security.octopus.keys.KeyManager;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;

public class DHKeySelector extends KeySelector {

    @Override
    public void init() {
        // We need to make sure that no CDI based keyManager is selected.
        // But that means for the moment we just need to override the method and keep it empty.
    }

    @Override
    protected KeyManager getKeyManager() {
        return DHKeyManager.getInstance();
    }
}
