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
package be.atbash.keys.server;

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.util.EncryptionHelper;
import be.atbash.keys.diffiehellman.AlicePublicData;
import be.atbash.keys.diffiehellman.BobPublicData;
import be.atbash.keys.diffiehellman.DHKeyExchangeManager;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import java.util.List;

@Path("/")
@ApplicationScoped
public class KeyServerManagementResource {

    @Inject
    private DHKeyExchangeManager exchangeManager;

    private ServerKeyManager serverKeyManager;

    @PostConstruct
    public void init() {
        serverKeyManager = ServerKeyManager.getInstance();
    }

    @Path("/exchangeInfo")
    @POST
    public String exchangeInfo(String aliceData) {
        JWTDecoder decoder = new JWTDecoder();
        AlicePublicData alicePublicData = decoder.decode(aliceData, AlicePublicData.class).getData();

        BobPublicData bobPublicData = exchangeManager.acknowledgeExchange(alicePublicData);

        JWTParameters parameters = new JWTParametersNone();

        JWTEncoder encoder = new JWTEncoder();
        return encoder.encode(bobPublicData, parameters);

    }

    @GET
    @Path("/newKey/{exchangeId}")
    public String newKey(@PathParam("exchangeId") String exchangeId) {
        // exchangeId = alice-{UUID}
        SecretKey secretKey = exchangeManager.defineSecretKey(exchangeId);

        String tenantId = exchangeManager.getTenantId(exchangeId);
        String kid = serverKeyManager.generateKeys(tenantId);

        SelectorCriteria criteria = SelectorCriteria.newBuilder()
                .withId(kid)
                .withAsymmetricPart(AsymmetricPart.PRIVATE)
                .withDiscriminator(tenantId)
                .build();
        List<AtbashKey> keyList = serverKeyManager.retrieveKeys(criteria);


        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.NONE).build();
        String json = new JWTEncoder().encode(keyList.get(0), parameters);

        return EncryptionHelper.encode(json, secretKey);
    }


}
