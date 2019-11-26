/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.dynssl;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/** Unit test for {@link SslCertificateUtils}. */
public class SslCertificateUtilsUnitTest {

    private static final String CERT_DATA = "Certificate data...";
    private static final String CERT_DATA_BASE64 =
            Base64.getEncoder().encodeToString(CERT_DATA.getBytes(StandardCharsets.US_ASCII));

    private static final String PRIV_KEY_DATA = "Private key...";
    private static final String PRIV_KEY_BASE64 =
            Base64.getEncoder().encodeToString(PRIV_KEY_DATA.getBytes(StandardCharsets.US_ASCII));

    private static final String FISH_CERT_BASE64 =
            "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV\n"
                    + "BAoTD1N1cGVyZmlzaCwgSW5jLjELMAkGA1UEBxMCU0YxCzAJBgNVBAgTAkNBMQsw\n"
                    + "CQYDVQQGEwJVUzEYMBYGA1UEAxMPU3VwZXJmaXNoLCBJbmMuMB4XDTE0MDUxMjE2\n"
                    + "MjUyNloXDTM0MDUwNzE2MjUyNlowWzEYMBYGA1UEChMPU3VwZXJmaXNoLCBJbmMu\n"
                    + "MQswCQYDVQQHEwJTRjELMAkGA1UECBMCQ0ExCzAJBgNVBAYTAlVTMRgwFgYDVQQD\n"
                    + "Ew9TdXBlcmZpc2gsIEluYy4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOjz\n"
                    + "Shh2Xxk/sc9Y6X9DBwmVgDXFD/5xMSeBmRImIKXfj2r8QlU57gk4idngNsSsAYJb\n"
                    + "1Tnm+Y8HiN/+7vahFM6pdEXY/fAXVyqC4XouEpNarIrXFWPRt5tVgA9YvBxJ7SBi\n"
                    + "3bZMpTrrHD2g/3pxptMQeDOuS8Ic/ZJKocPnQaQtAgMBAAGjgcAwgb0wDAYDVR0T\n"
                    + "BAUwAwEB/zAdBgNVHQ4EFgQU+5izU38URC7o7tUJml4OVoaoNYgwgY0GA1UdIwSB\n"
                    + "hTCBgoAU+5izU38URC7o7tUJml4OVoaoNYihX6RdMFsxGDAWBgNVBAoTD1N1cGVy\n"
                    + "ZmlzaCwgSW5jLjELMAkGA1UEBxMCU0YxCzAJBgNVBAgTAkNBMQswCQYDVQQGEwJV\n"
                    + "UzEYMBYGA1UEAxMPU3VwZXJmaXNoLCBJbmMuggkA0vwTh6lE3OcwDQYJKoZIhvcN\n"
                    + "AQEFBQADgYEApHyg7ApKx3DEcWjzOyLi3JyN0JL+c35yK1VEmxu0Qusfr76645Oj\n"
                    + "1IsYwpTws6a9ZTRMzST4GQvFFQra81eLqYbPbMPuhC+FCxkUF5i0DNSWi+kczJXJ\n"
                    + "TtCqSwGl9t9JEoFqvtW+znZ9TqyLiOMw7TGEUI+88VAqW0qmXnwPcfo=\n";

    private static final String FISH_PRIV_KEY_BASE64 =
            "";

    private static final String FISH_CERT_BASE64_STR =
            "";

    @Test
    public void shouldReturnEmptyByteArrayIfNotAbleToFindCertSectionInPemData() {
        // Given
        String pem = CERT_DATA_BASE64;
        // When
        byte[] cert = SslCertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfBeginCertTokenWasNotFoundInPemData() {
        // Given
        String pem = CERT_DATA_BASE64 + SslCertificateUtils.END_CERTIFICATE_TOKEN;
        // When
        byte[] cert = SslCertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfEndCertTokenWasNotFoundInPemData() {
        // Given
        String pem = SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN + CERT_DATA_BASE64;
        // When
        byte[] cert = SslCertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfEndCertTokenIsBeforeBeginCertTokenInPemData() {
        // Given
        String pem =
                SslCertificateUtils.END_CERTIFICATE_TOKEN
                        + CERT_DATA_BASE64
                        + SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN;
        // When
        byte[] cert = SslCertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnCertificateBetweenBeginAndEndCertTokensFromPemData() {
        // Given
        String pem =
                SslCertificateUtils.BEGIN_CERTIFICATE_TOKEN
                        + CERT_DATA_BASE64
                        + SslCertificateUtils.END_CERTIFICATE_TOKEN;
        // When
        byte[] cert = SslCertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(CERT_DATA.length())));
        assertThat(cert, is(equalTo(CERT_DATA.getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfNotAbleToFindPrivKeySectionInPemData() {
        // Given
        String pem = PRIV_KEY_BASE64;
        // When
        byte[] cert = SslCertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfBeginPrivKeyTokenWasNotFoundInPemData() {
        // Given
        String pem = PRIV_KEY_BASE64 + SslCertificateUtils.END_PRIVATE_KEY_TOKEN;
        // When
        byte[] cert = SslCertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfEndPrivKeyTokenWasNotFoundInPemData() {
        // Given
        String pem = SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN + PRIV_KEY_BASE64;
        // When
        byte[] cert = SslCertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnEmptyByteArrayIfEndPrivKeyTokenIsBeforeBeginPrivKeyTokenInPemData() {
        // Given
        String pem =
                SslCertificateUtils.END_PRIVATE_KEY_TOKEN
                        + PRIV_KEY_BASE64
                        + SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN;
        // When
        byte[] cert = SslCertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    public void shouldReturnPrivateKeyBetweenBeginAndEndPrivKeyTokensFromPemData() {
        // Given
        String pem =
                SslCertificateUtils.BEGIN_PRIVATE_KEY_TOKEN
                        + PRIV_KEY_BASE64
                        + SslCertificateUtils.END_PRIVATE_KEY_TOKEN;
        // When
        byte[] cert = SslCertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(PRIV_KEY_DATA.length())));
        assertThat(cert, is(equalTo(PRIV_KEY_DATA.getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    public void shouldConvertPem2Keystore() throws Exception {
        Provider provider = new BouncyCastleProvider();
        try {
            // Given
            Security.addProvider(provider);
            byte[] cert = Base64.getMimeDecoder().decode(FISH_CERT_BASE64);
            byte[] key = Base64.getMimeDecoder().decode(FISH_PRIV_KEY_BASE64);
            // When
            KeyStore ks = SslCertificateUtils.pem2KeyStore(cert, key);
            // Then
            assertThat(ks, is(notNullValue()));
            assertThat(ks.getCertificate("cert-alias"), is(notNullValue()));
        } finally {
            Security.removeProvider(provider.getName());
        }
    }

    @Test
    public void shouldConvertStringCertToAndFromKeyStore() throws Exception {
        // Given
        String certBase64 = FISH_CERT_BASE64_STR;
        // When
        KeyStore ks = SslCertificateUtils.string2Keystore(certBase64);
        String newCertBase64 = SslCertificateUtils.keyStore2String(ks);
        // Then
        assertThat(newCertBase64, is(equalTo(certBase64)));
    }
}
