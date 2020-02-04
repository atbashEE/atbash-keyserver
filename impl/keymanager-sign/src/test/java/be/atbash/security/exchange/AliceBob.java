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
package be.atbash.security.exchange;

import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import be.atbash.keys.diffiehellman.AlicePublicData;
import be.atbash.keys.diffiehellman.BobPublicData;
import be.atbash.keys.diffiehellman.DHKeyExchangeManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class AliceBob implements Runnable {
    private String aliceData;
    private String bobData;

    private boolean aliceRunning = false;
    private byte[] ciphertext;

    private String receivedString;
    private Exception aliceException;
    private Exception bobException;

    private DHKeyExchangeManager exchangeManager;

    public void run() {
        exchangeManager = DHKeyExchangeManager.getInstance();
        if (!aliceRunning) {
            aliceRunning = true;
            doAlice();
        } else {
            doBob();
        }
    }


    private void doAlice() {
        try {
            // Step 1:  Alice generates a key pair

            // Step 2:  Alice sends the public key and the
            // 		Diffie-Hellman key parameters to Bob
            AlicePublicData alicePublicData = exchangeManager.startExchange("someTenant");

            JWTParameters parameters = new JWTParametersNone();

            JWTEncoder encoder = new JWTEncoder();
            aliceData = encoder.encode(alicePublicData, parameters);

            while (bobData == null) {
                Thread.sleep(100);
            }

            JWTDecoder decoder = new JWTDecoder();
            BobPublicData bobPublicData = decoder.decode(bobData, BobPublicData.class).getData();


            // Step 4 part 1:  Alice performs the first phase of the
            //		protocol with her private key

            // Step 4 part 2:  Alice performs the second phase of the
            //		protocol with Bob's public key

            // Step 4 part 3:  Alice can generate the secret key

            // Step 6:  Alice generates a AES key

            SecretKey key = exchangeManager.defineSecretKey(bobPublicData.getPublicKey().getKeyId());

            // Step 7:  Alice encrypts data with the key and sends
            //		the encrypted data to Bob
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            ciphertext = c.doFinal("Stand and unfold yourself".getBytes());

        } catch (Exception e) {
            aliceException = e;
        }
    }

    private void doBob() {
        try {
            // Step 3:  Bob uses the parameters supplied by Alice
            //		to generate a key pair and sends the public key
            while (aliceData == null) {
                Thread.sleep(100);
            }

            JWTDecoder decoder = new JWTDecoder();
            AlicePublicData alicePublicData = decoder.decode(aliceData, AlicePublicData.class).getData();

            BobPublicData bobPublicData = exchangeManager.acknowledgeExchange(alicePublicData);

            JWTParameters parameters = new JWTParametersNone();

            JWTEncoder encoder = new JWTEncoder();
            bobData = encoder.encode(bobPublicData, parameters);


            // Step 5 part 1:  Bob uses his private key to perform the
            //		first phase of the protocol

            // Step 5 part 2:  Bob uses Alice's public key to perform
            //		the second phase of the protocol.


            // Step 5 part 3:  Bob generates the secret key

            // Step 6:  Bob generates a AES key


            SecretKey key = exchangeManager.defineSecretKey(alicePublicData.getPublicKey().getKeyId());

            // Step 8:  Bob receives the encrypted text and decrypts it
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key);
            while (ciphertext == null) {
                Thread.sleep(100);
            }
            byte plaintext[] = c.doFinal(ciphertext);
            receivedString = new String(plaintext);
        } catch (Exception e) {
            bobException = e;
        }
    }

    public String getReceivedString() {
        return receivedString;
    }

    public Exception getAliceException() {
        return aliceException;
    }

    public Exception getBobException() {
        return bobException;
    }
}
