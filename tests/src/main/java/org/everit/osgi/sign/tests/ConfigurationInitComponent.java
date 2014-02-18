package org.everit.osgi.sign.tests;

/*
 * Copyright (c) 2011, Everit Kft.
 *
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyPair;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.UUID;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.keystore.file.FileBasedKeyStoreComponent;
import org.everit.osgi.sign.PropertyName;
import org.everit.osgi.sign.SignerComponent;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

@Component(immediate = true)
@Service(value = ConfigurationInitComponent.class)
public class ConfigurationInitComponent {

    private static final String KEY_STORE_TYPE = "BKS";

    public static final String PROVIDER_TARGET_FILTER = "(providerName=BC)";

    private static final String KEY_STORE_URL;

    private static final String KEY_STORE_PASSWORD = UUID.randomUUID().toString();

    private static final KeyPair KEY_PAIR;

    private static final String PRIVATE_KEY_ALIAS = UUID.randomUUID().toString();

    private static final char[] PRIVATE_KEY_PASSWORD = UUID.randomUUID().toString().toCharArray();

    private static final String PUBLIC_KEY_ALIAS = UUID.randomUUID().toString();

    @Reference(bind = "bindConfigAdmin")
    private ConfigurationAdmin configAdmin;

    static {
        KEY_PAIR = TestKeyStoreUtil.generateKeyPair("RSA", "SHA1PRNG");
        File configurationDir = new File("configuration");
        configurationDir.mkdirs();
        String keyStoreLocation = "configuration/test-key-store-" + UUID.randomUUID().toString();
        TestKeyStoreUtil.createBCKeyStore(KEY_STORE_TYPE, keyStoreLocation, KEY_STORE_PASSWORD,
                "SHA1WITHRSA", PRIVATE_KEY_ALIAS, KEY_PAIR.getPrivate(), PRIVATE_KEY_PASSWORD, PUBLIC_KEY_ALIAS,
                KEY_PAIR.getPublic());
        try {
            KEY_STORE_URL = new File(keyStoreLocation).toURI().toURL().toString();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        System.out.println("--- ");
    }

    @Activate
    public void activate(final BundleContext bundleContext) throws Exception {
        try {
            Dictionary<String, Object> keyStoreProps = new Hashtable<String, Object>();
            keyStoreProps.put(org.everit.osgi.keystore.file.PropertyName.PROVIDER_TARGET, PROVIDER_TARGET_FILTER);
            keyStoreProps.put(org.everit.osgi.keystore.file.PropertyName.KEY_STORE_URL, KEY_STORE_URL);
            keyStoreProps.put(org.everit.osgi.keystore.file.PropertyName.KEY_STORE_TYPE, KEY_STORE_TYPE);
            keyStoreProps.put(org.everit.osgi.keystore.file.PropertyName.KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
            String keyStorePid = getOrCreateConfiguration(FileBasedKeyStoreComponent.class.getName(), keyStoreProps);

            Dictionary<String, Object> signerProps = new Hashtable<String, Object>();
            signerProps.put(PropertyName.KEY_STORE_TARGET, "(" + Constants.SERVICE_PID + "=" + keyStorePid + ")");
            signerProps.put(PropertyName.PROVIDER_TARGET, PROVIDER_TARGET_FILTER);
            signerProps.put(PropertyName.PRIVATE_KEY_ALIAS, PRIVATE_KEY_ALIAS);
            signerProps.put(PropertyName.PRIVATE_KEY_PASSWORD, PRIVATE_KEY_PASSWORD);
            signerProps.put(PropertyName.PUBLIC_KEY_ALIAS, PUBLIC_KEY_ALIAS);
            String signerPid = getOrCreateConfiguration(SignerComponent.class.getName(), signerProps);

            Dictionary<String, Object> signerTestProps = new Hashtable<>();
            signerTestProps.put("signer.target", "(" + Constants.SERVICE_PID + "=" + signerPid + ")");
            getOrCreateConfiguration(SignerTestComponent.class.getName(), signerTestProps);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidSyntaxException e) {
            throw new RuntimeException(e);
        }
        System.out.println("--- +");
    }

    public void bindConfigAdmin(final ConfigurationAdmin configAdmin) {
        this.configAdmin = configAdmin;
    }

    private String getOrCreateConfiguration(final String factoryPid, final Dictionary<String, Object> props)
            throws IOException, InvalidSyntaxException {
        Configuration[] configurations = configAdmin.listConfigurations("(service.factoryPid=" + factoryPid + ")");
        if ((configurations != null) && (configurations.length > 0)) {
            return configurations[0].getPid();
        }
        Configuration configuration = configAdmin.createFactoryConfiguration(factoryPid, null);
        configuration.update(props);
        return configuration.getPid();
    }

}
