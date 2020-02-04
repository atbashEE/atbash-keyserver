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
package be.atbash.keys.diffiehellman;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;


public class AlicePublicData extends BobPublicData {

    private DHParameterSpec dhParameterSpec;


    public DHParameterSpec getDhParameterSpec() {
        if (dhParameterSpec == null) {
            // FIXME validate if properties are present in map and have correct type
            // This to cover the fact that p and g are not in the correct type (int or BigDecimal)
            BigInteger gValue = new BigInteger(properties.get("g").toString());
            BigInteger pValue = new BigInteger(properties.get("p").toString());
            dhParameterSpec = new DHParameterSpec(pValue, gValue, (int) properties.get("l"));
        }
        return dhParameterSpec;
    }

    public void setDhParameterSpec(DHParameterSpec dhParameterSpec) {
        this.dhParameterSpec = dhParameterSpec;
    }

}
