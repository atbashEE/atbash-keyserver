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
package be.atbash.keys.server.example.app2;

import be.atbash.ee.security.octopus.jwt.decoder.JWTData;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

@Path("/test")
@ApplicationScoped
public class TestResource {

    @Inject
    private JWTDecoder jwtDecoder;

    @Inject
    private KeySelector keySelector;

    @POST
    public String doSomeTest(String data) {
        JWTData<TestData> jwtData = jwtDecoder.decode(data, TestData.class, keySelector, null);

        return jwtData.getData().getName() + " - "+jwtData.getData().getAge();
    }
}
