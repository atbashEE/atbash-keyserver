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

import be.atbash.keys.diffiehellman.BobPublicData;

import javax.json.bind.serializer.JsonbSerializer;
import javax.json.bind.serializer.SerializationContext;
import javax.json.stream.JsonGenerator;
import java.util.Base64;

public class BobPublicDataWriter implements JsonbSerializer<BobPublicData> {

    @Override
    public void serialize(BobPublicData bobPublicData, JsonGenerator jsonGenerator, SerializationContext ctx) {
        jsonGenerator.writeStartObject()
                .write("tenantId", bobPublicData.getTenantId())
                .write("kid", bobPublicData.getPublicKey().getKeyId())
                .write("publicKey", Base64.getUrlEncoder().withoutPadding().encodeToString(bobPublicData.getPublicKey().getKey().getEncoded()))
                .writeEnd();
    }
}
