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
package be.atbash.keys.diffiehellman.json;

import be.atbash.json.writer.CustomBeanJSONEncoder;
import be.atbash.keys.diffiehellman.AlicePublicData;
import be.atbash.util.base64.Base64Codec;
import be.atbash.util.exception.AtbashUnexpectedException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

public class AlicePublicDataJSONEncoder extends CustomBeanJSONEncoder<AlicePublicData> {

    private static final List<String> PASSTHROUGH_KEYS = Arrays.asList("p", "g", "l", "kid");

    public AlicePublicDataJSONEncoder() {
        super(AlicePublicData.class);
    }

    @Override
    protected void setCustomValue(AlicePublicData current, String key, Object value) {
        if (PASSTHROUGH_KEYS.contains(key)) {
            current.addProperty(key, value);
        }
        if ("publicKey".equals(key)) {
            handlePublicKey(current, value.toString());
        }

    }

    private void handlePublicKey(AlicePublicData current, String value) {
        try {
            KeyFactory kf = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(Base64Codec.decode(value));
            PublicKey pk = kf.generatePublic(x509Spec);

            current.addProperty("publicKey", pk);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AtbashUnexpectedException(e);
        }
    }
}