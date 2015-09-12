/*
 * Copyright (c) 2015. Sergey Gershtein, convert-me.com
 * All rights reserved.
 *
 * NB. Key formats
 *
 * Generate a 2048-bit RSA private key
 *
 * $ openssl genrsa -out private_key.pem 2048
 *
 * Convert private Key to PKCS#8 format (so Java can read it)
 *
 * $ openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
 *
 * Output public key portion in DER format (so Java can read it)
 *
 * $ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
 */

package net.gershtein;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * <p>This is a class that works with our simple signed json specification.
 * The class methods are provided to add a digital signature to a JSON
 * represented as a String and to verify a signature of a JSON
 * </p><p>
 * The calls to the object can be chained for easy operations:<br>
 * {@code
 * verifiedJSON = new SignedJSON().setPublicKey(publicKey).verify(jsonString)
 * }</p>
 * Created by gershtein on 10.09.2015.
 */
public class SignedJSON {

    //region Various static constants

    /**
     * Tag. Just a tag
     */
    protected static final String TAG = SignedJSON.class.getSimpleName();

    /**
     * Key that holds the signature in JSON
     */
    public static final String SIGNATURE_KEY = "dgst_sha256_base64";

    /**
     * Every signed json starts with this string
     */
    private static final byte[] SIGNED_JSON_START_STRING =
            ("{\"" + SIGNATURE_KEY + "\":\"").getBytes();

    /**
     * Algorithm to use with {@link Signature}
     */
    public static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    /**
     * Algorithm to use with {@link KeyFactory}
     */
    public static final String KEY_ALGORITHM = "RSA";

    /**
     * Buffer size for reading keys from files
     */
    private static final int STREAM_BUFFER_SIZE = 1024 * 8;

    //endregion

    /**
     * Private key (required to digitally sign a JSON.
     * Must be in binary (der) format
     */
    private PrivateKey privateKey = null;

    /**
     * Public key (required to verify a signature)
     * Must be in binary (der) format
     */
    PublicKey publicKey = null;

    //region Various setters to set public/private key directly or from other means

    @SuppressWarnings("unused")
    public SignedJSON setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    @SuppressWarnings("unused")
    public SignedJSON setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /**
     * Set private key from binary byte[] in DER format
     *
     * @param privateKey binary DER representation of a private key
     * @return the SignedJSON object itself for chaining of calls
     * @throws NoSuchAlgorithmException in case our key algorithm is not supported
     * @throws InvalidKeySpecException  in case our key specification is not supported
     */
    @SuppressWarnings("UnusedReturnValue unused")
    public SignedJSON setPrivateKey(@Nullable byte[] privateKey)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        if (privateKey == null) {
            this.privateKey = null;
            return this;
        }

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        this.privateKey = keyFactory.generatePrivate(keySpec);

        return this;
    }

    /**
     * Set public key from binary byte[] in DER format
     *
     * @param publicKey binary DER representation of a public key
     * @return the SignedJSON object itself for chaining of calls
     * @throws NoSuchAlgorithmException in case our key algorithm is not supported
     * @throws InvalidKeySpecException  in case our key specification is not supported
     */
    @SuppressWarnings("UnusedReturnValue unused")
    public SignedJSON setPublicKey(@Nullable byte[] publicKey)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        if (publicKey == null) {
            this.publicKey = null;
            return this;
        }

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        this.publicKey = keyFactory.generatePublic(keySpec);

        return this;
    }

    /**
     * Set private key from InputStream (a file) containing binary key in DER format
     * This can be used to initialize the key from raw resource, e.g.
     * {@code setPrivateKey(openRawResource(R.raw.private_key))}
     *
     * @param stream open file with binary DER representation of a private key
     * @return the SignedJSON object itself for chaining of calls
     * @throws NoSuchAlgorithmException in case our key algorithm is not supported
     * @throws InvalidKeySpecException  in case our key specification is not supported
     * @throws IOException              in case there were problems reading data
     */
    @SuppressWarnings("unused")
    public SignedJSON setPrivateKey(InputStream stream)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            IOException {

        setPrivateKey(readStreamFully(stream));
        return this;
    }

    /**
     * Set public key from InputStream (a file) containing binary key in DER format
     * This can be used to initialize the key from raw resource, e.g.
     * {@code setPublicKey(openRawResource(R.raw.private_key))}
     *
     * @param stream open file with binary DER representation of a public key
     * @return the SignedJSON object itself for chaining of calls
     * @throws NoSuchAlgorithmException in case our key algorithm is not supported
     * @throws InvalidKeySpecException  in case our key specification is not supported
     * @throws IOException              in case there were problems reading data
     */
    @SuppressWarnings("unused")
    public SignedJSON setPublicKey(InputStream stream)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            IOException {

        setPublicKey(readStreamFully(stream));
        return this;
    }

    /**
     * private helper method to fully read all data from a given InputStream.
     * Be careful with the data size, it might not fit into memory if the file is large
     * The stream is not automatically closed after the data is read
     *
     * @param inputStream the stream to read
     * @return the data from the stream as byte[] array
     * @throws IOException
     */
    private byte[] readStreamFully(InputStream inputStream)
            throws IOException {
        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
        byte[] buffer = new byte[STREAM_BUFFER_SIZE];
        int length;
        while ((length = inputStream.read(buffer)) != -1) {
            byteOutput.write(buffer, 0, length);
        }
        return byteOutput.toByteArray();
    }

    //endregion


    /**
     * Verify the provided signed JSON represented as a STRING.
     * If signature is good, the method returns JSON String with the signature removed.
     * If the signature is wrong, a BadSignatureException is thrown.
     * The behavior of the method in case there is no signature depends on the mode flags.
     * If it's {@code NO_SIGNATURE_FAIL}, the method throws exception when there is no signature.
     * If it's {@code NO_SIGNATURE_OK}, the method does not throw an exception, but returns null
     * when there is no signature.
     *
     * @param json a signed JSON represented in a byte[] array
     * @param mode verification mode flag (see {@link SignedJSON.VERIFY_MODE})
     * @return JSON with the signature removed in case of good verified signature,
     * null in case there was no signature and mode was {@code NO_SIGNATURE_OK}
     *
     * @throws BadSignatureException    in case the signature was not verified
     * @throws net.gershtein.SignedJSON.BadJsonFormatException if json can't be parsed
     * @throws NullPointerException     if there was no public key to verify the signature
     * @throws NoSuchAlgorithmException if our signing algorithm is not supported
     * @throws InvalidKeyException      if our key is invalid
     * @throws SignatureException       if the signature was not properly initialized
     */
    @SuppressWarnings("unused")
    public
    @Nullable
    byte[] verify(@NonNull byte[] json,
                  @NonNull VERIFY_MODE mode)
            throws BadSignatureException,
            NullPointerException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            BadJsonFormatException {

        // we need a public key to verify a signature
        if (publicKey == null)
            throw new NullPointerException("No public key to verify a signature");

        JsonBytes jsonBytes = new JsonBytes(json);

        //region Process the case when signature was not found
        if (!jsonBytes.hasSignature()) {

            // signature not found
            switch (mode) {

                case NO_SIGNATURE_OK:
                    return null;

                case NO_SIGNATURE_FAIL:
                    throw new BadSignatureException("No signature found");

                default:
                    throw new RuntimeException("Internal Error: not supported mode: " + mode);
            }

        }
        //endregion

        // get the signature out to a separate byte[] array
        byte[] sig64 = jsonBytes.getSignature();
        assert( sig64!=null ); // can't be null since hasSignature() was true earlier

        // get the original unsigned json
        byte[] plainJson = jsonBytes.getWithoutSignature();

        // Initialize a signature object with our public key
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);

        // add the data to the signature object
        signature.update(plainJson);

        // and finally verify it with our base64-encoded signature
        try {
            if (!signature.verify(Base64.decode(sig64, Base64.DEFAULT))) {
                throw new BadSignatureException("Signature not verified with the provided key");
            }
        } catch (IllegalArgumentException e) {
            // could not base64-decode the signature
            throw new BadSignatureException("Signature not verified with the provided key");
        }

        // return JSON with the signature removed
        return plainJson;
    }

    /**
     * Digitally sign the provided json represented as a byte[] array
     *
     * @param json json in a byte[] array to sign represented
     * @return signed json as a byte[] array
     * @throws NullPointerException     if there was no private key to sign
     * @throws NoSuchAlgorithmException if our signing algorithm is not supported
     * @throws InvalidKeyException      if our key is invalid
     * @throws SignatureException       if the signature was not properly initialized
     */
    @SuppressWarnings("unused")
    public
    @NonNull
    byte[] sign(@NonNull byte[] json)
            throws NullPointerException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            BadJsonFormatException {

        // we need a public key to verify a signature
        if (privateKey == null)
            throw new NullPointerException("No private key to sign the json");

        JsonBytes jsonBytes = new JsonBytes(json);

        // Initialize a signature object with our private key
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);

        // sign our json data
        signature.update(jsonBytes.getJson());
        byte[] sig64 = Base64.encode(signature.sign(), Base64.NO_WRAP);

        // return json with the signature embedded
        return jsonBytes.embedSignature(sig64);

    }

    /**
     * Signature verification mode flags
     * {@code NO_SIGNATURE_OK} means signature is not required (NOT RECOMMENDED!)  If there is a signature,
     * ikt is checked, if there's none, verification succeeds anyway
     * {@code NO_SIGNATURE_FAIL} means strict mode (RECOMMENDED) when verification only succeeds if there
     * is a correct signature present
     */
    public enum VERIFY_MODE {
        NO_SIGNATURE_OK,    // if there is no signature, verification succeeds
        NO_SIGNATURE_FAIL,  // if there is no signature, verification fails
    }


    /**
     * Exception that is thrown when json can't be parsed.
     * Even though SignedJSON class does not parse json and does not
     * care about it content, it still need it to start and end with
     * curly brackets.  And if there is a signature its value must be
     * enclosed in double quotes.
     */
    public class BadJsonFormatException extends Exception {
        /**
         * Constructs a new {@code BadJsonFormatException} with the current stack trace
         * and the specified detail message.
         *
         * @param detailMessage the detail message for this exception.
         */
        public BadJsonFormatException(String detailMessage) {
            super(detailMessage);
        }
    }

    /**
     * Exception that is thrown when signature verification is not passed
     */
    public class BadSignatureException extends Exception {
        /**
         * Constructs a new {@code BadSignatureException} with the current stack trace
         * and the specified detail message.
         *
         * @param detailMessage the detail message for this exception.
         */
        public BadSignatureException(String detailMessage) {
            super(detailMessage);
        }
    }

    /**
     * Internal private helper class to work with the json represented as a byte[] array
     */
    private class JsonBytes {

        //region Whitespace characters constants
        /**
         * White space characters
         */
        private static final byte BYTE_SPACE = 32;
        private static final byte BYTE_TAB = 9;
        private static final byte BYTE_CR = 13;
        private static final byte BYTE_LF = 10;
        //endregion

        /**
         * The current json as a byte[] array
         * It is supposed to be whitespace-trimmed on both ends
         * The constructor automatically does the trimming for us
         */
        private final byte[] json;

        /**
         * Does our json have a signature embedded?
         * The field is null if we have not checked yet
         */
        private Boolean hasSignature = null;

        /**
         * Byte positions in json where the whole signature block and
         * the signature itself starts and ends
         * the pos member is used temporarily by skipSequence when scanning for the signature
         */
        private Integer sigBlockStart, sigBlockEnd, sigStart, sigEnd, pos;

        /**
         * Constructor initialize the json by trimming the whitespace on both ends
         *
         * @param json json byte[]
         * @throws IllegalArgumentException in case the agrument does not look like json
         */
        public JsonBytes(@NonNull byte[] json)
                throws BadJsonFormatException {
            this.json = trimWhitespace(json);

            // check it looks like json, throw BadJsonFormatException otherwise
            if (this.json[0] != "{".getBytes()[0] ||
                    this.json[this.json.length - 1] != "}".getBytes()[0]) {
                Log.e(TAG,"JsonBytes constructor called with wrong json argument (must start and end with {}");
                throw new BadJsonFormatException("JSON must start with { and end with }");
            }
        }

        /**
         * Get the whole json
         *
         * @return the json array
         */
        public
        @NonNull
        byte[] getJson() {
            return json;
        }

        /**
         * return the signature from our json
         *
         * @return the signature or null if there is no signature
         */
        public
        @Nullable
        byte[] getSignature()
                throws BadJsonFormatException {

            if (hasSignature()) {
                // there is a signature
                byte[] signature = new byte[sigEnd - sigStart + 1];
                System.arraycopy(json, sigStart, signature, 0, sigEnd - sigStart + 1);
                return signature;

            } else {
                // no signature
                return null;
            }

        }

        /**
         * Get the json with the signature removed
         * If there's no signature this method returns the original json
         * If there is a signature this method returns json without the signature block
         *
         * @return the json without the signature block
         */
        public
        @NonNull
        byte[] getWithoutSignature()
                throws BadJsonFormatException {
            if (hasSignature()) {
                byte[] result = new byte[json.length - (sigBlockEnd - sigBlockStart + 1)];
                System.arraycopy(json, 0, result, 0, sigBlockStart);
                System.arraycopy(json, sigBlockEnd + 1, result, sigBlockStart, json.length - sigBlockEnd - 1);
                return result;
            } else {
                return json;
            }
        }

        /**
         * Embed the given signature to the json
         * This method does not modify the object, it only returns the json
         * with the given signature embedded
         * NB. The sig64 should be already base64-encoded
         * NB. This method does not care if there is already a signature, it can add another one
         * @param sig64 the signature value to embed.
         *              This should only be the value of the signature,
         *              not the whole signature block
         * @return the json with the signature embedded
         */
        public
        @NonNull
        byte[] embedSignature(@NonNull byte[] sig64) {

            ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
            byteOutput.write(SIGNED_JSON_START_STRING, 0, SIGNED_JSON_START_STRING.length);
            byteOutput.write(sig64, 0, sig64.length);
            // TODO: 12.09.2015 Do not add a comma if there is no next field (empty json)
            byteOutput.write(("\",").getBytes(), 0, 2);

            // store all the rest
            byteOutput.write(json, 1, json.length - 1);

            // return the resulting signed json
            return byteOutput.toByteArray();

        }

        /**
         * Does our json have a signature?
         *
         * @return true if is has, false if it does not
         */
        public boolean hasSignature()
                throws BadJsonFormatException {

            if (hasSignature == null) {
                // we have not yet scanned the json for the signature, let's do it now
                findSignature();
            }
            return hasSignature;
        }

        /**
         * Scan the json and find the signature there is there is one
         */
        private void findSignature() throws BadJsonFormatException {

            if (hasSignature != null)
                return;

            // we start scanning from the very start
            pos = 0;

            // look for the signature key at the current position
            if (!skipSequence(SIGNED_JSON_START_STRING)) {
                // not a signature key which means there is no signature
                hasSignature = false;
                return;
            }

            // the key is there.  Mark the start positions
            sigBlockStart = 1;  // signature block always start right after the opening {
            sigStart = pos;     // the signature itself starts right here

            while (pos < json.length && json[pos] != "\"".getBytes()[0]) {
                pos++;
            }
            sigEnd = pos - 1;

            if(!skipSequence("\",")) {
                // there was no closing double quote up till the end of json.
                // or there was no comma after the closing double quote
                // in any case that's a format error
                sigEnd = sigStart = null;
                hasSignature = false;
                Log.d(TAG,"JSON format error - no closing double quote for the signature");
                throw new BadJsonFormatException(
                        "JSON format error - no closing double quote for the signature");
            }

            sigBlockEnd = pos - 1;
            sigBlockStart = 1; // the signature block starts always right after the opening {
            hasSignature = true;

        }

        /**
         * Trim leading and trailing whitespace in a byte array
         *
         * @param bytes original byte array
         * @return a copy of a byte array with leading and trailing whitespace trimmed
         */
        private
        @NonNull
        byte[] trimWhitespace(@NonNull byte[] bytes) {

            int trimStart = 0;

            // skip all leading whitespace
            while (trimStart < bytes.length &&
                    (bytes[trimStart] == BYTE_SPACE ||
                            bytes[trimStart] == BYTE_TAB ||
                            bytes[trimStart] == BYTE_CR ||
                            bytes[trimStart] == BYTE_LF)) {
                trimStart++;
            }

            // if we reached the end of the array, it was all whitespace
            if (trimStart >= bytes.length)
                return new byte[0];

            int trimEnd = bytes.length - 1;

            // skip all trailing whitespace
            while (trimEnd >= 0 &&
                    (bytes[trimEnd] == BYTE_SPACE ||
                            bytes[trimEnd] == BYTE_TAB ||
                            bytes[trimEnd] == BYTE_CR ||
                            bytes[trimEnd] == BYTE_LF)
                    ) {
                trimEnd--;
            }

            // copy the part that should stay from bytes to result
            byte[] result = new byte[trimEnd - trimStart + 1];
            System.arraycopy(bytes, trimStart, result, 0, trimEnd - trimStart + 1);

            return result;
        }

        /**
         * Helper method to check the json byte array contains exactly the
         * given byte sequence at current position pos.  If yes, the pos is moved to the end of
         * the sequence and true is returned.  If not, false is returned
         *
         * @param seq   the sequence of characters that should match
         * @return true if the sequence is there, false otherwise
         */
        private boolean skipSequence(@NonNull byte[] seq) {
            int i = 0;
            while (pos < json.length && i < seq.length && json[pos] == seq[i]) {
                pos++;
                i++;
            }

            return (i == seq.length);
        }

        /**
         * Helper method to check the json byte array contains exactly the
         * given String at current position pos.  If yes, the pos is moved to the end of
         * the sequence and true is returned.  If not, false is returned
         * The string is converted to bytes as is for the default encoding
         *
         * @param seq   the String that should match
         * @return true if the string is there, false otherwise
         */
        private boolean skipSequence(@NonNull String seq) {
            return skipSequence(seq.getBytes());
        }

    }
}
