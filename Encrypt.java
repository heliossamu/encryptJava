import javax.crypto.Cipher;  
import javax.crypto.spec.IvParameterSpec;  
import javax.crypto.spec.SecretKeySpec;  

import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

public class Encrypt {

  public byte[] encryptDES(byte[] entrada, byte[] chave, EncryptMode mode, byte[] iv){
     try{
        SecretKeySpec key = new SecretKeySpec(chave, "DES");

        if(mode == EncryptMode.ECB){
           Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
           des.init(Cipher.ENCRYPT_MODE, key);
           return des.doFinal(entrada);
        }else if(mode == EncryptMode.CBC){
           Cipher des = Cipher.getInstance("DES/CBC/NoPadding");
           IvParameterSpec ips = new IvParameterSpec(iv);
           des.init(Cipher.ENCRYPT_MODE, key, ips);
           return des.doFinal(entrada);
        }
     }
     catch(Exception ex){
        ex.printStackTrace();
     }
     return null;
  }

  public byte[] decryptDES(byte[] entrada, byte[] chave, EncryptMode mode, byte[] iv){
     try{
        SecretKeySpec key = new SecretKeySpec(chave, "DES");
        if(mode == EncryptMode.ECB){
           Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
           des.init(Cipher.DECRYPT_MODE, key);
           return des.doFinal(entrada);
        }else if(mode == EncryptMode.CBC){
           Cipher des = Cipher.getInstance("DES/CBC/NoPadding");
           IvParameterSpec ips = new IvParameterSpec(iv);
           des.init(Cipher.DECRYPT_MODE, key, ips);
           return des.doFinal(entrada);
        }
     }catch(Exception ex){
        ex.printStackTrace();
     }
     return null;
  }

  //entrada precisa ser multiplo de 8
  //chave precisa ter 16 bytes - 2TDEA
  public byte[] encryptTripleDES(byte[] entrada, byte[] chave, EncryptMode mode, byte[] iv){
     int i = 0, j = 0;
     //k1 = k3
     byte[] k1 = new byte[8];
     byte[] k2 = new byte[8];

     for(i = 0; i < 8; i++){
        k1[i] = chave[i];
     }

     for(i = 8; i < 16; i++){
        k2[j] = chave[i];
        j++;
     }

     byte[] retorno = encryptDES(entrada, k1, mode, iv);
     retorno = decryptDES(retorno, k2, mode, iv);
     retorno = encryptDES(retorno, k1, mode, iv);
     return retorno;
  }


  public byte[] decryptTripleDES(byte[] entrada, byte[] chave, EncryptMode mode, byte[] iv){
     int i = 0, j = 0;
     //k1 = k3
     byte[] k1 = new byte[8];
     byte[] k2 = new byte[8];

     for(i = 0; i < 8; i++){
        k1[i] = chave[i];
     }

     for(i = 8; i < 16; i++){
        k2[j] = chave[i];
        j++;
     }

     byte[] retorno = decryptDES(entrada, k1, mode, iv);
     retorno = encryptDES(retorno, k2, mode, iv);
     retorno = decryptDES(retorno, k1, mode, iv);
     return retorno;
  }


  public byte[] encryptMK_WK(byte[] entrada, byte[] masterKey, byte[] workingKey, EncryptMode mode, byte[] iv){
     byte[] decryptedWorkingKey = decryptTripleDES(workingKey, masterKey, mode, iv);
     return encryptTripleDES(entrada, decryptedWorkingKey, mode, iv);
  }

}