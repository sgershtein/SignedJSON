package net.gershtein.signedjsontest;

import android.app.Activity;
import android.content.res.Resources;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import net.gershtein.SignedJSON;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class MainActivity extends Activity {

    /**
     * Buffer size for reading keys from files
     */
    private static final int STREAM_BUFFER_SIZE = 1024 * 8;

    private static final String TAG = MainActivity.class.getSimpleName();


    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView textView = (TextView)findViewById(R.id.textView);

        String result = "Starting tests\n";

        // initializing the object for signing/verifying
        SignedJSON signedJson = new SignedJSON();
        Log.d(TAG,"Object initialized");

        Resources resources = getResources();

        // adding the keys to the object
        try {

            InputStream inputStream = resources.openRawResource(R.raw.publickey);
            signedJson.setPublicKey(inputStream);
            inputStream.close();

            inputStream = resources.openRawResource(R.raw.privatekey);
            signedJson.setPrivateKey(inputStream);
            inputStream.close();

        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG,"NoSuchAlgorithmException",e);
            e.printStackTrace();
            finish();
        } catch (InvalidKeySpecException e) {
            Log.e(TAG,"InvalidKeySpecException",e);
            e.printStackTrace();
            finish();
        } catch (IOException e) {
            Log.e(TAG,"IOException",e);
            e.printStackTrace();
            finish();
        }

        Log.d(TAG,"Keys read and installed");
        result = result + "Keys read and installed\n";

        // read resources to byte[] arrays
        byte[] jsonPlainResource = null;
        byte[] jsonSignedResource = null;
        try {

            InputStream inputStream = getResources().openRawResource(R.raw.plain);
            jsonPlainResource = readStreamFully(inputStream);
            inputStream.close();

            inputStream = getResources().openRawResource(R.raw.signed);
            jsonSignedResource = readStreamFully(inputStream);
            inputStream.close();

        } catch (IOException e) {
            Log.e(TAG,"IOException",e);
            e.printStackTrace();
            finish();
            return;
        }

        Log.d(TAG,"Json resources read");
        result = result + "json resources read\n";
        result = result + "Plain >>>"+new String(jsonPlainResource)+"<<<\n";


        byte[] jsonPlainResourceSigned = null;
        try {
            // sign plain json file
            jsonPlainResourceSigned = signedJson.sign(jsonPlainResource);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG,"NoSuchAlgorithmException",e);
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            Log.e(TAG,"InvalidKeyException",e);
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            Log.e(TAG,"SignatureException",e);
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadJsonFormatException e) {
            Log.e(TAG,"BadJsonFormatException",e);
            e.printStackTrace();
            finish();
        }
        assert( jsonPlainResourceSigned != null );

        String jsonPlainSignedString = new String(jsonPlainResourceSigned);
        String jsonSignedResourceString = new String(jsonSignedResource);

        Log.d(TAG,"Signed plain json: "+jsonPlainSignedString);
        result = result + "Signed in java>>>"+jsonPlainSignedString+"<<<\n";
        Log.d(TAG,"Signed resource: "+jsonSignedResourceString);
        result = result + "Signed resource>>>"+jsonSignedResourceString+"<<<\n";

        // verify the signature we've just created
        byte[] jsonSignedVerified = null;
        try {
            jsonSignedVerified = signedJson.verify(jsonPlainResourceSigned,
                    SignedJSON.VERIFY_MODE.NO_SIGNATURE_FAIL);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            result = result + "*** ERROR: Signature verification FAILED\n";
            Log.e(TAG,"*** ERROR: Signature verification failed for plain signed in java",e);
        } catch (SignedJSON.BadJsonFormatException e) {
            Log.e(TAG,"BadJsonFormatException",e);
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadSignatureException e) {
            result = result + "*** ERROR: Signature verification FAILED for plain signed in java\n";
            Log.e(TAG, "*** ERROR: Signature verification FAILED for plain signed in java");
        } finally {
            result = result + "OK: Signature verification passed for plain signed in java\n";
            Log.e(TAG,"OK: Signature verification passed for plain signed in java");
        }

        // compare the returned verified json with the original unsigned
        if( jsonSignedVerified != null ) {
            String jsvString = new String(jsonSignedVerified).trim();
            String jprString = new String(jsonPlainResource).trim();
            result = result + "Original>>>" + jprString + "<<<\n";
            result = result + "Verified>>>" + jsvString + "<<<\n";
        }

        // verify the signature we've just created
        byte[] jsonSignedResourceVerified = null;
        try {
            jsonSignedResourceVerified = signedJson.verify(jsonSignedResource,
                    SignedJSON.VERIFY_MODE.NO_SIGNATURE_FAIL);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            result = result + "*** ERROR: Signature verification FAILED for signed resource\n";
            Log.e(TAG, "*** ERROR: Signature verification failed for signed resource", e);
        } catch (SignedJSON.BadJsonFormatException e) {
            e.printStackTrace();
        } catch (SignedJSON.BadSignatureException e) {
            result = result + "*** ERROR: Signature verification FAILED for signed resource\n";
            Log.e(TAG, "*** ERROR: Signature verification FAILED for signed resource");
        } finally {
            result = result + "OK: Signature verification passed for signed resource\n";
            Log.e(TAG,"OK: Signature verification passed for signed resource");
        }

        // trying to verify unsigned (should report no signature
        try {
            byte[] vResult = signedJson.verify(jsonPlainResource,
                    SignedJSON.VERIFY_MODE.NO_SIGNATURE_OK);
            if( vResult == null ) {
                result = result + "OK: No signature found in unsigned resource\n";
                Log.e(TAG,"OK: No signature found in unsigned resource");
            } else {
                result = result + "*** ERROR: Signature verification PASSED for unsigned resource\n";
                Log.e(TAG, "*** ERROR: Signature verification PASSED for unsigned resource");
           }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadJsonFormatException e) {
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadSignatureException e) {
            result = result + "*** ERROR: Signature verification FAILED for unsigned resource with NO_SIGNATURE_OK mode\n";
            Log.e(TAG, "*** ERROR: Signature verification FAILED for unsigned resource with NO_SIGNATURE_OK mode");
        }

        // now try to modify a signed json and verify it
        jsonSignedResource[jsonSignedResource.length-3] = "q".getBytes()[0];
        try {
            byte[] vResult = signedJson.verify(jsonSignedResource,
                    SignedJSON.VERIFY_MODE.NO_SIGNATURE_OK);
            if( vResult == null ) {
                result = result + "*** ERROR: null returned verifying altered signed resource\n";
                Log.e(TAG,"*** ERROR: null returned verifying altered signed resource");
            } else {
                result = result + "*** ERROR: Signature verification PASSED for altered signed resource\n";
                Log.e(TAG, "*** ERROR: Signature verification PASSED for altered signed resource");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadJsonFormatException e) {
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadSignatureException e) {
            result = result + "OK: Signature verification FAILED for altered signed resource\n";
            Log.e(TAG, "OK: Signature verification FAILED for altered signed resource");
        }

        // now try to modify a signature in json and verify it
        jsonPlainResourceSigned[40] = "q".getBytes()[0];
        try {
            byte[] vResult = signedJson.verify(jsonPlainResourceSigned,
                    SignedJSON.VERIFY_MODE.NO_SIGNATURE_OK);
            if( vResult == null ) {
                result = result + "*** ERROR: null returned verifying altered signature\n";
                Log.e(TAG,"*** ERROR: null returned verifying altered signature");
            } else {
                result = result + "*** ERROR: Signature verification PASSED for altered signature\n";
                Log.e(TAG, "*** ERROR: Signature verification PASSED for altered signature");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            result = result + "OK: SignatureException for altered signature\n";
            Log.e(TAG, "OK: SignatureException for altered signature");
        } catch (SignedJSON.BadJsonFormatException e) {
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadSignatureException e) {
            result = result + "OK: Signature verification FAILED for altered signature\n";
            Log.e(TAG, "OK: Signature verification FAILED for altered signature");
        }

        // signing an empty json
        byte[] emptyJson = " {  } ".getBytes();

        byte[] emptyJsonSigned = null;
        try {
            // sign empty json file
            emptyJsonSigned = signedJson.sign(emptyJson);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG,"NoSuchAlgorithmException",e);
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            Log.e(TAG,"InvalidKeyException",e);
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            Log.e(TAG,"SignatureException",e);
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadJsonFormatException e) {
            Log.e(TAG,"BadJsonFormatException",e);
            e.printStackTrace();
            finish();
        }
        assert( emptyJsonSigned != null );

        String emptyJsonSignedString = new String(emptyJsonSigned);
        Log.d(TAG,"Empty json signed: "+emptyJsonSignedString);
        result = result + "Empty json signed>>>"+emptyJsonSignedString+"<<<\n";

        // verifying signed empty json

        byte[] emptyJsonSignedVerified = null;
        try {
            emptyJsonSignedVerified = signedJson.verify(emptyJsonSigned,
                    SignedJSON.VERIFY_MODE.NO_SIGNATURE_FAIL);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            finish();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            finish();
        } catch (SignatureException e) {
            result = result + "*** ERROR: Empty json signature verification FAILED\n";
            Log.e(TAG,"*** ERROR: Empty json signature verification FAILED",e);
        } catch (SignedJSON.BadJsonFormatException e) {
            Log.e(TAG,"BadJsonFormatException",e);
            e.printStackTrace();
            finish();
        } catch (SignedJSON.BadSignatureException e) {
            result = result + "*** ERROR: Signature verification FAILED for signed empty json\n";
            Log.e(TAG, "*** ERROR: Signature verification FAILED for signed empty json");
        } finally {
            result = result + "OK: Signature verification passed for signed empty json\n";
            Log.e(TAG,"OK: Signature verification passed for signed empty json");
        }

        // compare the returned verified json with the original unsigned
        if( emptyJsonSignedVerified != null ) {
            String ejsvString = new String(emptyJsonSignedVerified).trim();
            String ejString = new String(emptyJson).trim();
            result = result + "Original>>>" + ejString + "<<<\n";
            result = result + "Verified>>>" + ejsvString + "<<<\n";
        }

        result = result + "\n------------------------\nTests are done\n";
        Log.d(TAG,"All tests are done");

        textView.setText(result);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

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

}
