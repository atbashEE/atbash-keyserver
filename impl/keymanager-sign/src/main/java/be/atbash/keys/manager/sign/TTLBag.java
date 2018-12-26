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
package be.atbash.keys.manager.sign;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class TTLBag<E> {

    private long timeToLive;

    private List<Element> contents = new ArrayList<>();

    public TTLBag(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public void add(E item) {
        contents.add(new Element(item, System.currentTimeMillis() + timeToLive));
    }

    public List<E> currentItems() {
        long time = System.currentTimeMillis();

        List<E> result = new ArrayList<>();
        Iterator<Element> iterator = contents.iterator();
        while (iterator.hasNext()) {
            Element element = iterator.next();
            if (element.expires > time) {
                iterator.remove();
            } else {
                result.add(element.item);
            }
        }

        return result;
    }

    private class Element {

        E item;
        long expires;

        Element(E item, long expires) {
            this.item = item;
            this.expires = expires;
        }

    }

}