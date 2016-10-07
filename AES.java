import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;

public class AES extends Crypto {

	static final int MODE = 0;
	static final int KEY = 1;
	static final int PLAINTEXT = 2;

	static final char ENC = 'e';
	static final char DEC = 'd';
	
	public void test() {
		System.out.println("Call to test");
	}
	public static void read(BufferedReader a){
		try{
			String  rl = null;
			while ((rl = a.readLine()) != null) {
            System.out.println(rl);
			}  
		 }
		catch (IOException e) {
			e.printStackTrace();
		}	
	}
	
	public static void main(String[] args) throws Exception {
		AES aes_265 = new AES();
		File key = new File(args[KEY]);
		File input = new File(args[PLAINTEXT]);
		BufferedReader keyReader = new BufferedReader(new FileReader(key));
		BufferedReader inputReader = new BufferedReader(new FileReader(input));
		System.out.println("Hello World!");
		aes_265.test();
		
		System.out.println("THE KEY IS\n");
		read(keyReader);
		System.out.println("THE INPUT IS\n");
		read(inputReader);
		keyReader.close();
		inputReader.close();
		
		//System.out.println(args[MODE]);
		//System.out.println(args[KEY]);
		//System.out.println(args[PLAINTEXT]);
		// open file in java
		// http://stackoverflow.com/questions/3806062/how-to-open-a-txt-file-and-read-numbers-in-java
	}
}