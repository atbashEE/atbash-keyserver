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

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.keys.writer.KeyEncoderParameters;
import be.atbash.ee.security.octopus.keys.writer.KeyWriterFactory;
import be.atbash.ee.security.octopus.nimbus.jwk.JWK;
import be.atbash.ee.security.octopus.nimbus.jwk.JWKSet;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

@Path("/keys")
@ApplicationScoped
public class KeysResource {

    @Inject
    private KeyWriterFactory keyWriterFactory;

    private ServerKeyManager keyManager;

    @PostConstruct
    public void init() {
        keyManager = ServerKeyManager.getInstance();
    }

    @GET
    @Path("{tenantId}")
    public String getKeys(@PathParam("tenantId") String tenantId) {
        SelectorCriteria criteria = SelectorCriteria.newBuilder()
                .withDiscriminator(tenantId)
                .withAsymmetricPart(AsymmetricPart.PUBLIC)
                .build();

        List<AtbashKey> keys = keyManager.retrieveKeys(criteria);

        KeyEncoderParameters parameters = new KeyEncoderParameters();

        List<JWK> jwkList = new ArrayList<>();

        try {
            for (AtbashKey key : keys) {
                byte[] bytes = this.keyWriterFactory.writeKeyAsJWK(key, parameters);

                jwkList.add(JWK.parse(new String(bytes)));
            }
        } catch (ParseException e) {
            throw new AtbashUnexpectedException(e);
        }
        return new JWKSet(jwkList).toJSONObject().toString();
    }
}
