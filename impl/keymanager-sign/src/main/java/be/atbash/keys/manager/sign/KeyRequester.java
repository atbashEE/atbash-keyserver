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
package be.atbash.keys.manager.sign;

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.util.EncryptionHelper;
import be.atbash.keys.diffiehellman.AlicePublicData;
import be.atbash.keys.diffiehellman.BobPublicData;
import be.atbash.keys.diffiehellman.DHKeyExchangeManager;
import be.atbash.keys.manager.sign.config.KeyManagerConfiguration;
import be.atbash.keys.manager.sign.rest.KeyServerManagementService;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.eclipse.microprofile.rest.client.RestClientBuilder;

import javax.crypto.SecretKey;
import java.net.MalformedURLException;
import java.net.URL;

public class KeyRequester {

    private DHKeyExchangeManager exchangeManager = DHKeyExchangeManager.getInstance();

    private String keyServerRootUrl;
    private String tenantId;

    public KeyRequester() {
        KeyManagerConfiguration configuration = KeyManagerConfiguration.getInstance();
        keyServerRootUrl = configuration.getKeyServerRootURL();
        tenantId = configuration.getKeyServerTenantId();
    }

    public AtbashKey requestKeyFromServer() {
        AlicePublicData alicePublicData = exchangeManager.startExchange(tenantId);

        String aliceData = getEncodedData(alicePublicData);

        try {
            KeyServerManagementService service = RestClientBuilder.newBuilder()
                    .baseUrl(new URL(keyServerRootUrl))
                    .build(KeyServerManagementService.class);

            String bobData = service.startExchange(aliceData);

            JWTDecoder decoder = new JWTDecoder();
            BobPublicData bobPublicData = decoder.decode(bobData, BobPublicData.class).getData();

            String encryptedKey = service.newKey(alicePublicData.getPublicKey().getKeyId());

            SecretKey secretKey = exchangeManager.defineSecretKey(bobPublicData.getPublicKey());

            String key = EncryptionHelper.decode(encryptedKey, secretKey);
            return new JWTDecoder().decode(key, AtbashKey.class).getData();

        } catch (MalformedURLException e) {
            // Not entirely correct.  But when moved to config, it is no issue
            throw new AtbashUnexpectedException(e);
        }
    }

    private String getEncodedData(AlicePublicData alicePublicData) {
        JWTParameters parameters = new JWTParametersNone(); // TODO non or JWT specified by parameters

        JWTEncoder encoder = new JWTEncoder();
        return encoder.encode(alicePublicData, parameters);
    }
}
