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
package be.atbash.keys.diffiehillman.json;

import be.atbash.json.JSONObject;
import be.atbash.json.writer.JSONWriter;
import be.atbash.keys.diffiehillman.BobPublicData;
import be.atbash.util.base64.Base64Codec;

import java.io.IOException;

public class BobPublicDataWriter implements JSONWriter<BobPublicData> {

    @Override
    public <E extends BobPublicData> void writeJSONString(E value, Appendable out) throws IOException {
        JSONObject result = new JSONObject();
        result.appendField("tenantId", value.getTenantId());
        result.appendField("kid", value.getPublicKey().getKeyId());
        result.appendField("publicKey", Base64Codec.encodeToString(value.getPublicKey().getKey().getEncoded(), true));

        result.writeJSONString(out);
    }
}
