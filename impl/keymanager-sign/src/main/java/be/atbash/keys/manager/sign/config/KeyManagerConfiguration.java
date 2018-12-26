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
package be.atbash.keys.manager.sign.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
@ModuleConfigName("Remote Key Manager configuration")
public class KeyManagerConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getKeyServerRootURL() {
        String result = getOptionalValue("key.server.url", String.class);
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("Parameter key.server.url is required and must be a valid URL");
        }

        return result;
    }

    @ConfigEntry
    public String getKeyServerTenantId() {
        String result = getOptionalValue("key.server.tenantId", String.class);
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("Parameter key.server.tenantId is required");
        }

        return result;
    }

    private static KeyManagerConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static KeyManagerConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new KeyManagerConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
