/**
 * Abstract for accessing Crypto.
 */
public abstract class Crypto {
	/**
	 * Callers can use these constant variable for better manage this encryption program. Feel free to change around in case it
	 * does not serve the purposes.
	*/
	static final int MODE = 0;
	static final int KEY = 1;
	static final int INPUTTEXT = 2;

	static final char ENC = 'e';
	static final char DEC = 'd';

	static final String ENCEXTENSION = ".enc";
	static final String DECEXTENSION = ".dec";

	static final int NUMBEROFROUNDS = 14;

	/**
	 * Read the contents of the file.
	 *
	 * @param fileName
	 *        The name of the file.
	 * @return the contents of the file.
	 * @throws FileNotFoundException
	 *         File does not exist.
	 * @throws IOException
	 *         Failed or interrupted I/O operations.
	*/
	abstract public String readFile(String fileName, boolean flag);

	/**
	 * Write the contents of the @variable contentForWrite to the file.
	 *
	 * @param fileName
	 *        The name of the file.
	 * @throws IOException
	 *         Failed or interrupted I/O operations.
	*/
	abstract public void writeFile(String fileName);

	/**
	 * Check if the mode or keyfile name or input file name is empty.
	*/
	abstract public void checkEmpty();

	/**
	 * Check if the mode is either equal to @constant ENC or @constant DEC.
	*/
	abstract public void checkIfValidMode();

	/**
	 * Check if the key file or input file contains invalid character.
	*/
	abstract public void checkIfContainsInvalidCharacter(String stringToCheck);

	/**
	 * Print sample command usage to help the user to get started with the program.
	*/
	abstract public void printSampleCommandUsage();

	/**
	 * Prepare to encrypt the message
	*/
	abstract public void prepareToEncrypt();

	/**
	 * Prepare to decrypt the message
	*/
	abstract public void prepareToDecrypt();
}