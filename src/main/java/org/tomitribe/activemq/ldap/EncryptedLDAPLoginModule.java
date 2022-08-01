/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe.activemq.ldap;

import org.apache.activemq.jaas.LDAPLoginModule;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.iv.RandomIvGenerator;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class EncryptedLDAPLoginModule extends LDAPLoginModule {

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map sharedState, final Map options) {

        final Map map = new HashMap();
        map.putAll(options);

        final String algorithm = (String) options.get("encryptionAlgorithm");

        final Set keySet = map.keySet();
        for (Object key : keySet) {


            if (! String.class.isInstance(key)) continue;

            final String optionsKey = (String) key;
            final Object value = map.get(optionsKey);

            if (! String.class.isInstance(value)) continue;

            final String optionsValue = (String) value;

            if (optionsValue.startsWith("ENC(") && optionsValue.endsWith(")")) {
                final String encodedValue = optionsValue.substring(4, optionsValue.length() - 1);
                final String password = System.getenv("ACTIVEMQ_ENCRYPTION_PASSWORD");
                if (password == null) {
                    continue;
                }

                final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
                encryptor.setPassword(password);
                if (algorithm != null) {
                    encryptor.setAlgorithm(algorithm);
                    // From Jasypt: for PBE-AES-based algorithms, the IV generator is MANDATORY"
                    if (algorithm.startsWith("PBE") && algorithm.contains("AES")) {
                        encryptor.setIvGenerator(new RandomIvGenerator());
                    }
                }
                try {
                    final String decrypted = encryptor.decrypt(encodedValue);
                    map.put(optionsKey, decrypted);
                } catch (EncryptionOperationNotPossibleException e) {
                    throw new RuntimeException("ERROR: Text cannot be decrypted, check your input and password and try again!", e);
                }
            }
        }

        super.initialize(subject, callbackHandler, sharedState, map);
    }
}
