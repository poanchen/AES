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
	static final char mBy2[] ={
		0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
		0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
		0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
		0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
		0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
		0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
		0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
		0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
		0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
		0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
		0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
		0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
		0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
		0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
		0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
		0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
	};
	static final char mBy3[] ={
		0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
		0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
		0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
		0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
		0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
		0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
		0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
		0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
		0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
		0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
		0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
		0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
		0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
		0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
		0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
		0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};
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
	public static void keyGen(){

		char[] rcon = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};
		int temp;
		int count=1;
		int flag=0;
		int [] tempcol=new int[4];
		for(int j=8;j<60;j++){
				if(j%4==0){
					
					for(int i=0;i<4;i++){
						tempcol[i]=keyExpansionArray[i][j-1];
					}
					temp=tempcol[0];
					if(flag==0){
					for(int z=0;z<3;z++){
						tempcol[z]=tempcol[z+1];
					}
					tempcol[3]=temp;
					}
					for(int x=0;x<4;x++){
						tempcol[x]= forwardTableLookUp(tempcol[x]);
					}
					
					for(int q=0;q<4;q++){
						tempcol[q]= tempcol[q]^keyExpansionArray[q][j-8];
					}
					if(flag==0){
					tempcol[0]=tempcol[0]^rcon[count++];
						flag=1;
					}else{
						flag=0;
					}
					for(int o=0;o<4;o++){
						keyExpansionArray[o][j]=tempcol[o];
					}
					
				}else{
					for(int h=0;h<4;h++){
						keyExpansionArray[h][j]=keyExpansionArray[h][j-1]^keyExpansionArray[h][j-8];
					}
				}	
				
		}
		
	}

	/**
	 * 
	 */
	public void mixColumns() {

	}

	/**
	 * 
	 */
	public static int[][] addRoundkey(int[][] message, int index) {
		
		int index=2;
		int col = 4*index;
		int []temp=new int[16];
		int []temp2=new int[16];
		int count=0;
		int count2=0;
		for(int j=0;j<4;j++){
			for(int i=0;i<4;i++){
				temp[count++]=message[i][j];
			}
		}
		for(int n=col;n<col+4;n++){
			for(int i=0;i<4;i++){
				temp2[count2++]=keyExpansionArray[i][n];
			}
		}
		for(int k=0;k<16;k++){
			temp[k]=temp[k]^temp2[k];
		}
		int count3=0;
		for(int q=0;q<4;q++){
			for(int w=0;w<4;w++){
				message[w][q]=temp[count3++];
			}
		}
		return message;
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
		keyGen();
		for (int o = 0; o < 60; o++) {
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
		/*
		if (new Character(mode).compareTo(ENC) == 0) {
			aes_265.prepareToEncrypt();
		}else {
			aes_265.prepareToDecrypt();
		}*/
		keyGen();
		addRoundkey();
		
		// contentForWrite = "this is a test haha";
		// aes_265.writeFile(keyFileName);
	}
}