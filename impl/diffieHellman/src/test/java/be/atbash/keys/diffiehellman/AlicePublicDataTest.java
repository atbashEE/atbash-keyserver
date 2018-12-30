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

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.DHGenerationParameters;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import be.atbash.util.base64.Base64Codec;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class AlicePublicDataTest {

    @Test
    public void encodeData() throws NoSuchAlgorithmException, InvalidKeySpecException {
        List<AtbashKey> keys = generateKeys();
        AtbashKey publicKey = findKey(keys, AsymmetricPart.PUBLIC);
        DHParameterSpec parameterSpec = ((DHPublicKey) publicKey.getKey()).getParams();

        AlicePublicData data = new AlicePublicData();
        data.setTenantId("someTenant");
        data.setPublicKey(publicKey);
        data.setDhParameterSpec(parameterSpec);

        JWTParameters parameters = new JWTParametersNone();

        JWTEncoder encoder = new JWTEncoder();
        String json = encoder.encode(data, parameters);

        JSONObject jsonObject = (JSONObject) JSONValue.parse(json);
        assertThat(jsonObject.getAsString("tenantId")).isEqualTo("someTenant");
        assertThat(jsonObject.getAsString("kid")).isEqualTo("kidValue");
        assertThat(jsonObject.getAsString("p")).isEqualTo("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
        assertThat(jsonObject.getAsString("g")).isEqualTo("2");
        assertThat(jsonObject.getAsString("l")).isEqualTo("512");

        byte[] bytes = Base64Codec.decode(jsonObject.getAsString("publicKey"));

        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(bytes);
        PublicKey pk = kf.generatePublic(x509Spec);

        BigInteger generatedY = ((DHPublicKey) publicKey.getKey()).getY();
        BigInteger jsonY = ((DHPublicKey) pk).getY();
        assertThat(generatedY).isEqualTo(jsonY);
    }

    @Test
    public void decodeData() {
        String json = "{\"kid\":\"kidValue\",\"p\":179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007,\"g\":2,\"tenantId\":\"someTenant\",\"publicKey\":\"MIIBIzCBmQYJKoZIhvcNAQMBMIGLAoGBAP__________yQ_aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu-pjsTmyJRSgh5jjQE3e-VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL_1y29Aa37e44a_taiZ-lrp8kEXxLH-ZJKGZR7OZTgf__________AgECAgICAAOBhAACgYA-VxU_A7WIOmH0MoB7LKWukfvxhbn7oZGdiU9UL-O7rn9ek6iBVY4h2NcqD0vUBAsPFAsj-D_VM_-uAlWH983hLeGDQ4meRpIy4APiZFZzOkwkZejTw4bL2uWpNIkhwdtBMxpnMxuWnw-nFMUeXaXuRJ9LBj3NP9mB4JYLnyNI2A\",\"l\":512}";
        JWTDecoder decoder = new JWTDecoder();
        AlicePublicData data = decoder.decode(json, AlicePublicData.class);

        assertThat(data.getTenantId()).isEqualTo("someTenant");
        assertThat(data.getDhParameterSpec().getP()).isEqualTo(new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007"));
        assertThat(data.getDhParameterSpec().getG()).isEqualTo(BigInteger.valueOf(2));
        assertThat(data.getDhParameterSpec().getL()).isEqualTo(512);

        assertThat(data.getPublicKey().getKeyId()).isEqualTo("kidValue");
        assertThat(data.getPublicKey().getKey()).isInstanceOf(DHPublicKey.class);

    }

    private List<AtbashKey> generateKeys() {
        DHGenerationParameters.DHGenerationParametersBuilder parameterBuilder = new DHGenerationParameters.DHGenerationParametersBuilder()
                .withKeySize(1024)
                .withKeyId("kidValue");

        return new KeyGenerator().generateKeys(parameterBuilder.build());
    }

    private AtbashKey findKey(List<AtbashKey> keys, AsymmetricPart asymmetricPart) {
        AsymmetricPartKeyFilter keyFilter = new AsymmetricPartKeyFilter(asymmetricPart);
        List<AtbashKey> filtered = keyFilter.filter(keys);
        if (filtered.size() != 1) {
            throw new AtbashUnexpectedException("Key not found for type " + asymmetricPart);
        }
        return filtered.get(0);
    }


}