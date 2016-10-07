import java.lang.*;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Abstract extension of {@code Crypto}.
 */
public class AES extends Crypto {
	/**
	 * Global variables to be use later.
	 */
	static char mode = 0;
	static String keyFileName = null;
	static String inputFileName = null;
	static String key = "";
	static String plainText = "";
	static String contentForWrite = "";

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
			System.out.println("Paramters cannot be empty!");
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
	
	public static void main(String[] args) throws Exception {
		AES aes_265 = new AES();
		
		try{
			if (args[MODE].length() > 1) aes_265.printSampleCommandUsage();
			mode = args[MODE].charAt(0);
			keyFileName = args[KEY];
			inputFileName = args[PLAINTEXT];
		}catch(ArrayIndexOutOfBoundsException e) {
			aes_265.printSampleCommandUsage();
		}

		aes_265.checkEmpty();
		aes_265.checkIfValidMode();
		key = aes_265.readFile(keyFileName);
		System.out.println("THE KEY IS");
		System.out.println(key);
		plainText = aes_265.readFile(inputFileName);
		System.out.println("THE INPUT IS");
		System.out.println(plainText);
		contentForWrite = "this is a test haha";
		aes_265.writeFile(keyFileName);
	}
}