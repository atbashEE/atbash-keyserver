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

import be.atbash.ee.security.octopus.jwt.parameter.JWTParameterHeaderDefaultProvider;
import be.atbash.keys.manager.sign.config.KeyManagerConfiguration;
import be.atbash.util.ordered.Order;

import java.util.HashMap;
import java.util.Map;

@Order(10)
public class JKUJWTParameterHeaderDefaultProvider implements JWTParameterHeaderDefaultProvider {

    private String jkuURL;

    public JKUJWTParameterHeaderDefaultProvider() {
        String rootURL = KeyManagerConfiguration.getInstance().getKeyServerRootURL();
        String tenantId = KeyManagerConfiguration.getInstance().getKeyServerTenantId();
        jkuURL = String.format("%s/keys/%s", rootURL, tenantId);
    }

    @Override
    public Map<String, Object> defaultHeaderValues() {
        HashMap<String, Object> result = new HashMap<>();
        result.put("jku", jkuURL);
        return result;
    }
}
