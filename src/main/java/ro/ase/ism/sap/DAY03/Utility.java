package ro.ase.ism.sap.DAY03;

public class Utility {
    public static String getHex(byte[] values){
        StringBuffer sb = new StringBuffer();
        for(byte b : values){
            sb.append(String.format(" %02x", b));
        }
        return sb.toString();
    }
}
