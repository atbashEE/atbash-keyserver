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
import be.atbash.json.annotate.JsonIgnore;
import be.atbash.json.parser.MappedBy;
import be.atbash.keys.diffiehellman.json.BobPublicDataJSONEncoder;
import be.atbash.keys.diffiehellman.json.BobPublicDataWriter;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

@MappedBy(writer = BobPublicDataWriter.class, beanEncoder = BobPublicDataJSONEncoder.class)
public class BobPublicData {

    private String tenantId;
    @JsonIgnore  // So that our beanEncoder gets the change to handle this field.
    private AtbashKey publicKey;

    protected Map<String, Object> properties = new HashMap<>();

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public AtbashKey getPublicKey() {
        if (publicKey == null) {
            // FIXME validate if properties are present in map and have correct type
            publicKey = new AtbashKey((String) properties.get("kid"), (Key) properties.get("publicKey"));
        }
        return publicKey;
    }

    public void setPublicKey(AtbashKey publicKey) {
        this.publicKey = publicKey;
    }

    public void addProperty(String key, Object value) {
        properties.put(key, value);
    }

}
