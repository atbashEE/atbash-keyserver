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
package be.atbash.keys.server.example.app1;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import org.eclipse.microprofile.rest.client.RestClientBuilder;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import java.net.MalformedURLException;
import java.net.URL;

@Path("/client")
@ApplicationScoped
public class ClientResource {

    @Inject
    private JWTEncoder jwtEncoder;

    @Inject
    private KeySelector keySelector;

    @GET
    public String testKeyServer() {
        TestData data = new TestData();
        data.setName("Atbash");
        data.setAge(2);

        SelectorCriteria selectorCriteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();

        AtbashKey key = keySelector.selectAtbashKey(selectorCriteria);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(key)
                .build();

        String encoded = jwtEncoder.encode(data, parameters);

        String result = null;

        try {
            TestService testService = RestClientBuilder.newBuilder().baseUrl(new URL("http://localhost:8280/app2"))
                    .build(TestService.class);

            result = testService.doTest(encoded);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return result;
    }
}
