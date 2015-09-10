/*
 * Copyright (c) 2015. Sergey Gershtein, convert-me.com
 * All rights reserved.
 */

package net.gershtein;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

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
     * Key that holds the signature in JSON
     */
    public static final String SIGNATURE_KEY = "dgst_sha256_base64";

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

    /**
     * White space characters
     */
    private static final byte BYTE_SPACE = 32;
    private static final byte BYTE_TAB = 9;
    private static final byte BYTE_CR = 13;
    private static final byte BYTE_LF = 10;
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
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicKey);
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
     * Helper method to check the the given byte array contains exactly the
     * given byte sequence at position pos.  If yes, the pos is moved to the end of
     * the sequence and true is returned.  If not, false is returned
     *
     * @param bytes the byte array to check
     * @param pos   the position to start
     * @param seq   the sequence of characters that should match
     * @return true if the sequence is there, false otherwise
     */
    private boolean skipSequence(@NonNull byte[] bytes,
                                 @NonNull Integer pos,
                                 @NonNull byte[] seq) {
        int i = 0;
        while (pos < bytes.length && i < seq.length && bytes[pos] == seq[i]) {
            pos++;
            i++;
        }
        return (i == seq.length);
    }

    /**
     * Helper method to check the the given byte array contains exactly the
     * given String at position pos.  If yes, the pos is moved to the end of
     * the sequence and true is returned.  If not, false is returned
     * The string is converted to bytes as is for the default encoding
     *
     * @param bytes the byte array to check
     * @param pos   the position to start
     * @param seq   the String that should match
     * @return true if the string is there, false otherwise
     */
    private boolean skipSequence(@NonNull byte[] bytes,
                                 @NonNull Integer pos,
                                 @NonNull String seq) {
        return skipSequence(bytes, pos, seq.getBytes());
    }

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
     * @throws BadSignatureException    in case the signature was not verified
     * @throws NullPointerException     if there was no public key to verify the signature
     * @throws NoSuchAlgorithmException if our signing algorithm is not supported
     * @throws InvalidKeyException      if our key is invalid
     * @throws SignatureException       if the signature was not properly initialized
     */
    @SuppressWarnings("unused")
    public byte[] verify(@NonNull byte[] json,
                         @NonNull VERIFY_MODE mode)
            throws BadSignatureException,
            NullPointerException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {

        // we need a public key to verify a signature
        if (publicKey == null)
            throw new NullPointerException("No public key to verify a signature");


        //region Find the signature in json
        // Let's find and extract a signature from the json provided
        Integer pos = 0;
        int sBlockStart = -1;   // position in json where our injected signature block starts
        int sBlockEnd = -1;     // position in json where our injected signature block ends
        int sigStart = -1;      // position in json where our signature starts
        int sigEnd = -1;        // position in json where our signature ends

        // skip all leading whitespace up to opening curly bracket
        while (pos < json.length) {
            if (json[pos] == BYTE_SPACE ||
                    json[pos] == BYTE_TAB ||
                    json[pos] == BYTE_CR ||
                    json[pos] == BYTE_LF) {
                pos++;
            } else {
                break;
            }
        }

        // skip the curly bracket itself
        if (skipSequence(json, pos, "{")) {

            // this is the place where our injected signature starts
            sBlockStart = pos;

            // skip the opening double quote
            // skip the SIGNATURE_KEY
            // skip  quote - equal - quote  sequence
            if (skipSequence(json, pos, "\"")
                    && skipSequence(json, pos, SIGNATURE_KEY)
                    && skipSequence(json, pos, "\":\"")) {

                // this is where the signature itself starts
                sigStart = pos;

                while (pos < json.length && json[pos] != "\"".getBytes()[0]) {
                    pos++;
                }
                sigEnd = pos - 1;

                // look for the closing quote and comma
                if (skipSequence(json, pos, "\",")) {
                    sBlockEnd = pos - 1;
                }

            }

        }
        //endregion

        //region Process the case when signature was not found
        if (sBlockStart < 0 || sBlockEnd < 0 || sigStart < 0 || sigEnd < 0) {

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
        byte[] sig64 = new byte[sigEnd - sigStart + 1];
        System.arraycopy(json, sigStart, sig64, 0, sigEnd - sigStart + 1);

        // remove the signature from the json
        byte[] plainJson = new byte[json.length - (sBlockEnd - sBlockStart + 1)];
        System.arraycopy(json, 0, plainJson, 0, sBlockStart);
        System.arraycopy(json, sBlockEnd + 1, plainJson, sBlockStart, json.length - sBlockEnd - 1);

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
    public byte[] sign(@NonNull byte[] json)
            throws NullPointerException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {

        // we need a public key to verify a signature
        if (privateKey == null)
            throw new NullPointerException("No private key to sign the json");

        // Initialize a signature object with our private key
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);

        // sign our json data
        signature.update(json);
        byte[] sig64 = Base64.encode(signature.sign(), Base64.NO_WRAP);

        // now construct the signed JSON with our signature injected
        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        // skip all leading whitespace up to opening curly bracket
        int pos = 0;
        while (pos < json.length) {
            if (json[pos] == BYTE_SPACE ||
                    json[pos] == BYTE_TAB ||
                    json[pos] == BYTE_CR ||
                    json[pos] == BYTE_LF) {
                pos++;
            } else {
                break;
            }
        }

        if( json[pos] != "{".getBytes()[0] ) {
            // it's not a curly bracket
            throw new IllegalArgumentException("JSON must start with opening curly bracket");
        }

        // store opening curly bracket and all the leading whitespace if any
        byteOutput.write(json,0,++pos);

        // store the key
        byte[] jsonSignature = ("\"" + SIGNATURE_KEY + "\":\"").getBytes();
        byteOutput.write(jsonSignature, 0, jsonSignature.length);
        byteOutput.write(sig64, 0, sig64.length);
        byteOutput.write(("\",").getBytes(), 0, 2);

        // store all the rest
        byteOutput.write(json,pos,json.length-pos);

        // return the resulting signed json
        return byteOutput.toByteArray();
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
     * Exception that is thrown when signature verification is not passed
     */
    public class BadSignatureException extends RuntimeException {
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
}
