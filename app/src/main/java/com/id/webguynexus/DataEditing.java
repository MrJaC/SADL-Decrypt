/*
    Credits to:
        https://mybroadband.co.za/forum/threads/decode-drivers-licence-barcode.382187/
        https://pastebin.com/gb049dfx
        https://github.com/ugommirikwe/sa-license-decoder
        https://pub.dev/packages/rsa_identification

        Stackoverflow in general.
 */
package com.id.webguynexus;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.Formatter;
import java.util.*;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

public class DataEditing extends BroadcastReceiver  {

    private com.honeywell.aidc.BarcodeReader barcodeReader;

    private static String key128 = "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MIGWAoGBAMqfGO9sPz+kxaRh/qVKsZQGul7NdG1gonSS3KPXTjtcHTFfexA4MkGA\n" +
            "mwKeu9XeTRFgMMxX99WmyaFvNzuxSlCFI/foCkx0TZCFZjpKFHLXryxWrkG1Bl9+\n" +
            "+gKTvTJ4rWk1RvnxYhm3n/Rxo2NoJM/822Oo7YBZ5rmk8NuJU4HLAhAYcJLaZFTO\n" +
            "sYU+aRX4RmoF\n" +
            "-----END RSA PUBLIC KEY-----";
    private static String key74 = "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MF8CSwC0BKDfEdHKz/GhoEjU1XP5U6YsWD10klknVhpteh4rFAQlJq9wtVBUc5Dq\n" +
            "bsdI0w/bga20kODDahmGtASy9fae9dobZj5ZUJEw5wIQMJz+2XGf4qXiDJu0R2U4\n" +
            "Kw==\n" +
            "-----END RSA PUBLIC KEY-----";
    private static PublicKey publicKey;
    private static byte[] dataT;


    //Vars
    public static String firstName = null;
    public static String surname = null;
    public static String idNumber = null;
    public static String licenseNumber = null;
    public static String licenseCountryofIssue = null;
    public static String gender = null;
    public static String idCountryOfIssue = null;

    public static String getGender(String idNumber){

        String id = idNumber.substring(6 , 10);
        int number = Integer.parseInt(id);
        String gender = "";

        if (number <= 4999)
        {
            gender = "F";
        }
        else
        {
            gender = "M";
        }

        return gender;
    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    public void onReceive(Context context, Intent intent) {

        String ScanResult = intent.getStringExtra("data");//Read the scan result from the Intent
        Log.d("SReult", "Scan Result: " + ScanResult);
        byte[] dataBytes = intent.getByteArrayExtra("dataBytes");


        //---------------------------------------------
        //Modify the scan result as needed.
        //---------------------------------------------
        //ScanResult.
        //Return the Modified scan result string
        Bundle bundle = new Bundle();
        assert dataBytes != null;
        if(dataBytes.length < 720){
            bundle.putString("data" , ScanResult);
            setResultExtras(bundle);
        }else{
            //
            bundle.putString("data", DecryptData(dataBytes));

            Log.d("Bundle","Bundle: " + bundle);
            //Log.d("length","Amount: " + byteData);
            setResultExtras(bundle);
        }

        //convert data to hex string
        assert ScanResult != null;

        Formatter formatter = new Formatter();
        for (byte b : dataBytes) {
            formatter.format("%02x", b);
        }
        String hex = formatter.toString();


    }
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static String DecryptData(byte[] data){
        //data.addAll(0, Collections.singleton("Id Number: " + idNumber));
       // Log.d("HexLength","HexLength: " + hex.length());
        Formatter formatter = new Formatter();
        for (byte b : data) {
            formatter.format("%02x", b);
        }
        String hex = formatter.toString();
        try {
            PublicKey rsaPub = readRSAPublicKey(key128);
            PublicKey rsaPub74 = readRSAPublicKey74(key74);
            Log.d("string key", "PubKeyPEM: " + rsaPub);

            // decrypts the message
            byte[] dectyptedText1 = null;
            byte[] dectyptedText2 = null;
            byte[] dectyptedText3 = null;
            byte[] dectyptedText4 = null;
            byte[] dectyptedText5 = null;
            byte[] dectyptedText6 = null;
            //128 key
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.DECRYPT_MODE, rsaPub);
            //74key
            Cipher cipher74 = Cipher.getInstance("RSA","BC");
            cipher74.init(Cipher.DECRYPT_MODE, rsaPub74);


            byte[] block1def = hexStringToByteArray(hex);
            Log.d("block", "Hex: " + block1def.length);
            Log.d("Byte length","Byte Length: " + data.length);

            byte[] block1Array = Arrays.copyOfRange(block1def, 6,   134);
            byte[] block2Array = Arrays.copyOfRange(block1def, 134, 262);
            byte[] block3Array = Arrays.copyOfRange(block1def, 262, 390);
            byte[] block4Array = Arrays.copyOfRange(block1def, 390, 518);
            byte[] block5Array = Arrays.copyOfRange(block1def, 518, 646);
            byte[] block6Array = Arrays.copyOfRange(block1def, 646, 720);


            dectyptedText1 = cipher.doFinal(block1Array);
            //not used.
            dectyptedText2 = cipher.doFinal(block2Array);
            dectyptedText3 = cipher.doFinal(block3Array);
            dectyptedText4 = cipher.doFinal(block4Array);
            dectyptedText5 = cipher.doFinal(block5Array);
            dectyptedText6 = cipher74.doFinal(block6Array);

            //
            //getSection1Values(dectyptedText1);
            //ArrayList<String> data = new ArrayList<>();
            ArrayList<String> values;
            ArrayList<String> values2;

            values = getSection1Values(dectyptedText1);

            //data
            idNumber    = values.get(14).trim().substring(0, 13);
            gender      = getGender(idNumber);
            firstName   = values.get(5);
            surname     = values.get(4);
            licenseNumber = values.get(13);
            idCountryOfIssue = values.get(7);
            licenseCountryofIssue = values.get(8);

            //String vehicleCodes =

            Log.d("IDNumber","IDNumber: " + idNumber + " / " + firstName + " / " + surname + " / " + gender + " / " + licenseNumber + " / " + licenseCountryofIssue + " / " + idCountryOfIssue + " / ");
            //end data

            //Log.d("LD","License Data: ",values);
            //128

        } catch (Exception e) {
            e.printStackTrace();
        }

        String barcodeData = surname + "|" + firstName + "|" + gender  + "|" + idNumber  + "|" + licenseNumber + "|" + idCountryOfIssue  + "|" + licenseCountryofIssue;


        return barcodeData;
    }
    @RequiresApi(api = Build.VERSION_CODES.O)
    //Decrypt using KEY
    private static PublicKey readRSAPublicKey(String pubkey64) throws Exception {
        byte[] key128block = Base64.decode(pubkey64.replaceAll("-----(BEGIN|END) RSA PUBLIC KEY-----", "").replaceAll("\n", "").getBytes(), Base64.DEFAULT);
        ASN1Primitive asn1Prime = new ASN1InputStream(key128block).readObject();
        org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPub = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(asn1Prime);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent()));
    }

    private static PublicKey readRSAPublicKey74(String pubkey74) throws Exception {
        byte[] key128block = Base64.decode(pubkey74.replaceAll("-----(BEGIN|END) RSA PUBLIC KEY-----", "").replaceAll("\n", "").getBytes(), Base64.DEFAULT);
        ASN1Primitive asn1Prime = new ASN1InputStream(key128block).readObject();
        org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPub = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(asn1Prime);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent()));
    }
    //Convert hex to byte
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    //Section

    public static int unsignedToBytes(byte b) {
        return b & 0xFF;
    }

    public static int searchBytes(byte[] myBytes)
    {
        for (int x = 0 ; x <= myBytes.length-1; x++ )
        {
            int dufus = unsignedToBytes(myBytes[x]);
            if (dufus == 224 || dufus == 225)
            {
                return x;
            }
        }
        return 0;
    }


    public static ArrayList<String> getSection1Values(byte[] bytes) {
        try {
            // var values = <String>[];
            ArrayList<String> values = new ArrayList<String>();
            int prevDeliminator = 0;
            while (values.size() < 13) {
                // int index = bytes.indexWhere((i) => i == 224 || i == 225);
                int index = searchBytes(bytes);

                if (prevDeliminator == 225) {
                    values.add("");

                    String value = new String(Arrays.copyOfRange( bytes, 0, index));
                    if (!value.isEmpty()) {
                        values.add(value);
                    }
                } else {
                    String value = new String(Arrays.copyOfRange( bytes, 0, index));
                    values.add(value);
                }

                prevDeliminator = unsignedToBytes(bytes[index]);
                bytes = Arrays.copyOfRange( bytes, index + 1, bytes.length);
                //bytes = Arrays.copyOf(bytes,index + 1);
            }
            values.add(new String(bytes));

            return values;
        } catch (Exception e) {
            throw e;
        }
    }
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static ArrayList<String> getSection2Values(byte[] bytes) {
        try {
            // Convert bytes to a hex string so that each letter represents a single nibble.
            Formatter formatter = new Formatter();
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }


            String nibbleString = formatter.toString();
            /*for (string x: hex
                 ) {
                nibbleString = nibbleString + hex;
            }*/
            //hex.forEach((hex) => nibbleString = nibbleString + hex);

            return getSection2ValuesFromNibbles(nibbleString);
        } catch (Exception e) {
            throw e;
        }
    }
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static ArrayList<String> getSection2ValuesFromNibbles(String nibbleString) {
        try {
            ArrayList<String> values = new ArrayList<String>();
            LocalDate localDate;
            while (values.size() < 12) {
                // If values.length is 0, 5, 7, or 8 - the next values is 2 nibbles (letters) long
                if (values.isEmpty() ||
                        values.size() == 5 ||
                        values.size() == 7 ||
                        values.size() == 11) {
                    //2 nibbles
                    values.add(nibbleString.substring(0, 2));
                    nibbleString = nibbleString.substring(2);
                    //continue;
                }

                // If values.length is 0, 5, 7, or 8 - the next values is a date, which can be
                // a single nibble or 8 nibbles long.
                if (values.size() == 1 ||
                        values.size() == 2 ||
                        values.size() == 3 ||
                        values.size() == 4 ||
                        values.size() == 6 ||
                        values.size() == 8 ||
                        values.size() == 9 ||
                        values.size() == 10) {
                    if (nibbleString.substring(0, 1) == "a") {
                        // 1 nibble
                        values.add(null);
                        nibbleString = nibbleString.substring(1);
                    } else {
                        // 8 nibbles

                        int year = Integer.parseInt(nibbleString.substring(0, 4));
                        int month =  Integer.parseInt(nibbleString.substring(4, 6));
                        int day =  Integer.parseInt(nibbleString.substring(6, 8));
                        LocalDate localDate1 = LocalDate.of(year,month,day);
                        values.add(localDate1.toString());
                        nibbleString = nibbleString.substring(8);
                    }
                    //continue;
                }
            }

            return values;
        } catch (Exception e) {
            throw e;
        }
    }
}
