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
package be.atbash.security.exchange;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DiffieHillman {

    // Make sure the DiffieHillman test stops properly as we have Threads which can get stuck
    //@Rule
    //public Timeout globalTimeout = new Timeout(2, TimeUnit.SECONDS);

    @Test
    public void testExchange() throws InterruptedException {
        AliceBob test = new AliceBob();
        new Thread(test).start();        // Starts Alice
        Thread.sleep(300); // Wait before Bob starts, otherwise they aren't correctly assigned in the run()

        Thread bob = new Thread(test);
        bob.start();        // Starts Bob
        bob.join();  // Wait until process is finished

        assertThat(test.getAliceException()).isNull();
        assertThat(test.getBobException()).isNull();
        assertThat(test.getReceivedString()).isEqualTo("Stand and unfold yourself");
    }

}
