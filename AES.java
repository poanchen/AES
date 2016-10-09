import java.lang.*;
import java.io.*;
import java.util.*;

/**
 * Abstract extension of {@code Crypto}.
 */
public class AES extends Crypto {
	/**
	 * Global variables to be use later.
	 */
	static int [][] keyExpansionArray = new int [4][60];
	static char mode = 0;
	static String keyFileName = null;
	static String inputFileName = null;
	static String key = "";
	static String inputText = "";
	static String contentForWrite = "";
	static final char forward[] = {
		0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};
	static final char inverse[] = {
		0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
		0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
		0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
		0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
		0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
		0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
		0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
		0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
		0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
		0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
		0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
		0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
		0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
		0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
	};

	public String readFile(String fileName) {
		String lineFromInputFile = null;
		String result = "";
		BufferedReader fileReader = null;
		File inputFileName = new File(fileName);

		try{
			fileReader = new BufferedReader(new FileReader(fileName));
			while ((lineFromInputFile = fileReader.readLine()) != null) {
				result += lineFromInputFile;
			}
		} catch (FileNotFoundException e) {
			System.out.println("Warning, '" + fileName + "' cannot be found! Please try again!");
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try{
				if (fileReader != null) {
					fileReader.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return result;
	}

	public int [] readKey(String tempKey, int index) {
		int a = 0;
		int j = 0;
		int [][] intArray = new int [4][4];
		char [] keyInChar = new char [32];
		char [] keyInByte = tempKey.toCharArray();
		int [] result = new int [32];
		String temp = "";

		for(int i = 0; i < 32; i++) {
			temp += keyInByte[i];
			a++;

			if (a == 2) {
				result[j] = Integer.parseInt(temp.trim(), 16);
				a = 0;
				temp = "";
				j++;
			}
		}
		a = 0;
		intArray = convert16BytesToFourByFourArray("", result);

		for (int i = index; i < index + 4; i++) {
			for (int q = 0; q < 4; q++) {
				// System.out.print(q + "-" + a);
				// System.out.print(q + "-" + i);
				keyExpansionArray[q][i] = intArray[q][a];
			}
			a++;
			// System.out.println(" ");
		}
		// 0-0 0-1 0-2 0-3 0-4 0-5 0-6 0-7
		// 1-0 1-1 1-2 1-3 1-4 1-5 1-6 1-7
		// 2-0 2-1 2-2 2-3 2-4 2-5 2-6 2-7
		// 3-0 3-1 3-2 3-3 3-4 3-5 3-6 3-7
		return result;
	}

	public void writeFile(String fileName) {
		String fileExtension = null;
		FileOutputStream fileWriter = null;
		File inputFileName;
		
		if (new Character(mode).compareTo(ENC) == 0) {
			fileExtension = ENCEXTENSION;
		}else {
			fileExtension = DECEXTENSION;
		}
		inputFileName = new File(fileName + fileExtension);

		try{
			if (!inputFileName.exists()) {
				inputFileName.createNewFile();
			}
			fileWriter = new FileOutputStream(inputFileName, false);
			byte[] contentInBytes = contentForWrite.getBytes();
			fileWriter.write(contentInBytes);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try{
				if (fileWriter != null) {
					fileWriter.flush();
					fileWriter.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public void checkEmpty() {
		if (mode == 0 || keyFileName == null || inputFileName == null) {
			System.out.println("Parameters cannot be empty!");
			System.exit(1);
		}
	}

	public void checkIfValidMode() {
		if (new Character(mode).compareTo(ENC) != 0 && new Character(mode).compareTo(DEC) != 0) {
			printSampleCommandUsage();
			System.exit(1);
		}
	}

	public void printSampleCommandUsage() {
		System.out.println("Please make sure you have all the paramters or you have the correct mode!");
		System.out.println("For example, java AES [mode] [key file name] [input file name]");
		System.out.println("For example, java AES e key.txt plaintext.txt");
		System.exit(1);
	}

	/**
	 * 
	 */
	public int [][] subBytes(int [][] intArray) {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				intArray[i][j] = forwardTableLookUp(intArray[i][j]);
			}
		}
		return intArray;
	}

	/**
	 * 
	 */
	public int[][] shiftRows(int[][] state) {
		
		
		//shifting R1
		int temp1 = state[1][0];
		for(int i=0;i<3;i++){
			state[1][i]=state[1][i+1];
		}
		state[1][3]=temp1;
		
		//shifting R2
		int temp2 =state[2][0];
		int temp3 =state[2][1];
		for(int k=0;k<2;k++){
			state[2][k]=state[2][k+2];
		}
		state[2][2]=temp2;
		state[2][3]=temp3;
		
		//shifting R3
		int temp4 =state[3][3];
		for(int j=3;j>0;j--){
			state[3][j]=state[3][j-1];
		}
		state[3][0]=temp4;
		
		return state;
	}

	/**
	 * 
	 */
	public void mixColumns() {

	}

	/**
	 * 
	 */
	public void addRoundkey() {

	}

	public static char forwardTableLookUp(int a) {
		return forward[a];
	}

	public int [][] convert16BytesToFourByFourArray(String sixteenBytesString, int [] keyArray) {
		int a = 0;
		int [][] intArray = new int [4][4];
		byte [] byteArrays = sixteenBytesString.getBytes();

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				try{
					if (sixteenBytesString == "") {
						intArray[j][i] = keyArray[a++];
					}else{
						intArray[j][i] = byteArrays[a++];
					}
				} catch (IndexOutOfBoundsException e) {
					intArray[j][i] = 0;
				}
			}
		}
		return intArray;
	}

	public void startEncryption(int [][] intArray) {
		// increment this to check the result
		int check = 1;
		int check1 = check - 1;
		
		for (int i = 0; i < check; i++) {
		// for (int i = 0; i < NUMBEROFROUNDS-1; i++) {

			if (i == check1) {
				for (int k = 0; k < 4; k++) {
					System.out.print("{");
					for (int j = 0; j < 4; j++) {
						System.out.print(intArray[k][j]);
						if (j + 1 != 4) {
							System.out.print(",");
						}else{
							System.out.print("}");
						}
					}
					System.out.println();
				}
				System.out.println();
			}

			intArray = subBytes(intArray);
			intArray = shiftRows(intArray);
			mixColumns();
			addRoundkey();
		}
	}

	public void prepareToEncrypt() {
		int a = 0;
		int count = 0;
		boolean flag = true;
		int numberOfFourByFourByteArray = (int) Math.ceil((double)inputText.getBytes().length/16);
		int [][] intArray = new int [4][4];
		int [] keyInArray = new int [16];
		char [] keyInByte = key.toCharArray();
		char [] inputTextInByte = inputText.toCharArray();
		String temp = "";
		String sixteenBytesString = "";

		for (int q = 0; q < 64; q++) {
			if (a < 32) {
				temp += keyInByte[q];
				a++;
			}
			if (a == 32) {
				if (flag) {
					readKey(temp, 0);
					flag = false;
				}else{
					readKey(temp, 4);
				}
				temp = "";
				a = 0;
			}
		}

		for (int o = 0; o < 8; o++) {
			for (int u = 0; u < 4; u++) {
				System.out.print(keyExpansionArray[u][o]);
				// System.out.print(o);
				// System.out.print(" ");
				// System.out.print(u);
			}
			System.out.println();
		}

		// for (int i = 0; i < inputTextInByte.length; i++) {
		// 	if (count < 16) {
		// 		sixteenBytesString += inputTextInByte[i];
		// 		count++;
		// 	}
		// 	if (count == 16) {
		// 		intArray = convert16BytesToFourByFourArray(sixteenBytesString, new int [0]);
		// 		startEncryption(intArray);
		// 		sixteenBytesString = "";
		// 		count = 0;
		// 	}
		// }

		// if (sixteenBytesString != "") {
		// 	intArray = convert16BytesToFourByFourArray(sixteenBytesString, new int [0]);
		// 	startEncryption(intArray);
		// }
	}

	public void prepareToDecrypt() {
		System.out.println("lets decrypt something!");
	}
	
	public static void main(String[] args) throws Exception {
		AES aes_265 = new AES();
		
		try{
			if (args[MODE].length() > 1) aes_265.printSampleCommandUsage();
			mode = args[MODE].charAt(0);
			keyFileName = args[KEY];
			inputFileName = args[INPUTTEXT];
		}catch(ArrayIndexOutOfBoundsException e) {
			aes_265.printSampleCommandUsage();
		}

		/**
	 	* Making sure if the user inputted parameters are what we expected.
	 	*/
		aes_265.checkEmpty();
		aes_265.checkIfValidMode();

		/**
	 	* Now, we should have the key as String from the key file.
	 	*/
		key = aes_265.readFile(keyFileName);
		// System.out.println("THE KEY IS");
		// System.out.println(key);

		/**
	 	* Now, we should have the message or text from the user's inputted file.
	 	*/
		inputText = aes_265.readFile(inputFileName);
		// System.out.println("THE INPUT IS");
		// System.out.println(inputText);

		if (new Character(mode).compareTo(ENC) == 0) {
			aes_265.prepareToEncrypt();
		}else {
			aes_265.prepareToDecrypt();
		}
		
		// contentForWrite = "this is a test haha";
		// aes_265.writeFile(keyFileName);
	}
}