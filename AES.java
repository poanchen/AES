public class AES extends Crypto {

	static final int MODE = 0;
	static final int KEY = 1;
	static final int PLAINTEXT = 2;

	static final char ENC = 'e';
	static final char DEC = 'd';
	
	public void test() {
		System.out.println("Call to test");
	}
	
	public static void main(String[] args) throws Exception {
		AES aes_265 = new AES();

		System.out.println("Hello World!");
		aes_265.test();
		System.out.println(args[MODE]);
		System.out.println(args[KEY]);
		System.out.println(args[PLAINTEXT]);
		// open file in java
		// http://stackoverflow.com/questions/3806062/how-to-open-a-txt-file-and-read-numbers-in-java
	}
}