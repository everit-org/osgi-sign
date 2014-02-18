package org.everit.osgi.sign;

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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.osgi.framework.BundleContext;
import org.osgi.service.cm.ConfigurationException;

@Component(metatype = true, configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = PropertyName.KEY_STORE_TARGET),
        @Property(name = PropertyName.PROVIDER_TARGET),
        @Property(name = PropertyName.PRIVATE_KEY_ALIAS),
        @Property(name = PropertyName.PRIVATE_KEY_PASSWORD, passwordValue = ""),
        @Property(name = PropertyName.PUBLIC_KEY_ALIAS)
})
@Service
public class SignerComponent implements Signer {

    @Reference(bind = "bindKeyStore", unbind = "unbindKeyStore")
    private KeyStore keyStore;

    @Reference(bind = "bindProvider", unbind = "unbindProvider")
    private Provider provider;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws ConfigurationException {
        String privateKeyAlias = getStringProperty(componentProperties, PropertyName.PRIVATE_KEY_ALIAS, false);
        String privateKeyPassword = getStringProperty(componentProperties, PropertyName.PRIVATE_KEY_PASSWORD, false);
        String publicKeyAlias = getStringProperty(componentProperties, PropertyName.PUBLIC_KEY_ALIAS, false);

        initPrivateKey(privateKeyAlias, privateKeyPassword);
        initPublicKey(publicKeyAlias);
    }

    public void bindKeyStore(final KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public void bindProvider(final Provider provider) {
        this.provider = provider;
        Security.addProvider(provider);
    }

    private String getStringProperty(final Map<String, Object> componentProperties, final String propertyName,
            final boolean required) throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if (required && (value == null)) {
            throw new ConfigurationException(propertyName, "required property not defined");
        }
        String stringValue = String.valueOf(value);
        if (required && stringValue.isEmpty()) {
            throw new ConfigurationException(propertyName, "required property not defined");
        }
        return stringValue;
    }

    private void initPrivateKey(final String privateKeyAlias, final String privateKeyPassword)
            throws ConfigurationException {
        privateKey = null;
        if (privateKeyAlias == null) {
            return;
        }
        PasswordProtection passwordProtection = new PasswordProtection(privateKeyPassword.toCharArray());
        try {
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(privateKeyAlias, passwordProtection);
            privateKey = privateKeyEntry.getPrivateKey();
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new ConfigurationException(null, "failed to load private key ["
                    + privateKeyAlias + "] from the given keystore");
        }
    }

    private void initPublicKey(final String publicKeyAlias) throws ConfigurationException {
        publicKey = null;
        if (publicKeyAlias == null) {
            return;
        }
        try {
            Certificate certificate = keyStore.getCertificate(publicKeyAlias);
            publicKey = certificate.getPublicKey();
        } catch (KeyStoreException e) {
            throw new ConfigurationException(null, "failed to load public key ["
                    + publicKeyAlias + "] from the given keystore");
        }
    }

    @Override
    public byte[] sign(final byte[] data, final String signatureAlgorithm,
            final AlgorithmParameterSpec algorithmParameterSpec, final SecureRandom secureRandom) {
        if (privateKey == null) {
            throw new SignerException("sign not available, private key not configured");
        }
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm, provider);
            if (algorithmParameterSpec != null) {
                signature.setParameter(algorithmParameterSpec);
            }
            if (secureRandom != null) {
                signature.initSign(privateKey, secureRandom);
            } else {
                signature.initSign(privateKey);
            }
            signature.update(data);
            return signature.sign();
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | SignatureException e) {
            throw new SignerException("failed to create signature", e);
        }
    }

    public void unbindKeyStore(final KeyStore keyStore) {
        this.keyStore = null;
    }

    public void unbindProvider(final Provider provider) {
        Security.removeProvider(provider.getName());
        this.provider = null;
    }

    @Override
    public boolean verify(final byte[] data, final byte[] signatureBytes, final String signatureAlgorithm,
            final AlgorithmParameterSpec algorithmParameterSpec) {
        if (publicKey == null) {
            throw new SignerException("verificaition not available, public key not configured");
        }
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm, provider);
            if (algorithmParameterSpec != null) {
                signature.setParameter(algorithmParameterSpec);
            }
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | SignatureException e) {
            throw new SignerException("failed to verifiy signature", e);
        }
    }

}
