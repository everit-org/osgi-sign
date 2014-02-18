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

import java.io.UnsupportedEncodingException;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.dev.testrunner.TestDuringDevelopment;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.everit.osgi.sign.Signer;
import org.junit.Assert;
import org.junit.Test;

@Component(immediate = true, metatype = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "SignerTestComponent"),
        @Property(name = "signer.target") })
@Service(value = SignerTestComponent.class)
@TestDuringDevelopment
public class SignerTestComponent {

    @Reference
    private Signer signer;

    @Activate
    public void activate() {
    }

    public void bindSigner(final Signer signer) {
        this.signer = signer;
    }

    @Test
    public void testSignAndVerify() throws UnsupportedEncodingException {
        byte[] data = "test".getBytes("UTF-8");
        String signatureAlgorithm = "SHA1WITHRSA";
        byte[] signatureBytes = signer.sign(data, signatureAlgorithm, null, null);
        boolean verify = signer.verify(data, signatureBytes, signatureAlgorithm, null);
        Assert.assertTrue(verify);
    }

}
