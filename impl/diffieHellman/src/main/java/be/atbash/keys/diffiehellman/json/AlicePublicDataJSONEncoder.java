/*
 * Copyright 2018-2020 Rudy De Busscher
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
package be.atbash.keys.diffiehellman.json;

import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.keys.diffiehellman.AlicePublicData;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.json.JsonObject;
import javax.json.bind.serializer.DeserializationContext;
import javax.json.bind.serializer.JsonbDeserializer;
import javax.json.stream.JsonParser;
import java.lang.reflect.Type;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

public class AlicePublicDataJSONEncoder implements JsonbDeserializer<AlicePublicData> {

    private static final List<String> PASSTHROUGH_KEYS = Arrays.asList("p", "g", "l", "kid");

    private void handlePublicKey(AlicePublicData current, String value) {
        try {
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(new Base64URLValue(value).decode());
            PublicKey pk = kf.generatePublic(x509Spec);

            current.addProperty("publicKey", pk);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AtbashUnexpectedException(e);
        }
    }

    @Override
    public AlicePublicData deserialize(JsonParser jsonParser, DeserializationContext ctx, Type rtType) {
        JsonObject jsonObject = jsonParser.getObject();

        AlicePublicData result = new AlicePublicData();
        for (String passthroughKey : PASSTHROUGH_KEYS) {
            Object obj = JSONObjectUtils.getJsonValueAsObject(jsonObject.get(passthroughKey));
            result.addProperty(passthroughKey, obj);
        }
        result.setTenantId(jsonObject.getString("tenantId"));
        handlePublicKey(result, jsonObject.getString("publicKey"));
        return result;
    }
}
