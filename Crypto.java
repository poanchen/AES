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
	 * Read the contents from the file line by line.
	 *
	 * @param fileName
	 *        The name of the file.
	 * @param flag
	 *        when flag is true, then we are reading input file (plaintext or encrypted text).
	 *        when flag is false, then we are reading the key file.
	 * @return the contents of the file. (if there are multiple line in the file, then each line will be separated by '\n')
	 * @throws IOException
	 *         Failed or interrupted I/O operations.
	 * @throws FileNotFoundException
	 *         File does not exist.
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
	 * Check if the given string contains any invalid character. If there is, alert the user and exit the program.
	 * @param stringToCheck
	 *        String that will be check one byte at the time.
	 * @param flag
	 *        So that we know whether it is a key or input file. So that, we have better warning message to user.
	*/
	abstract public void checkIfContainsInvalidCharacter(String stringToCheck, boolean flag);

	/**
	 * Whenever the user run the program without or missing needed parameters, then this function will get called.
	 * These warning message allow user to get better understanding on how to run the program.
	*/
	abstract public void printSampleCommandUsage();

	/**
	 * Prepare to encrypt or decrypt the message. First, we need to call the @method readKey for reading the key and
	 * store the result to the global @variable keyExpansionArray, so that keyGen can access it later for key expansion. Then,
	 * We call keyGen for creating the key expansion that is useful for the round key when we are actually doing the encryption
	 * or decryption. Then, since we are using the Electronic Code Book (ECB) mode, that is encode each block separately. Hence,
	 * we have a for loop that will call the @method convert16BytesToFourByFourArray for getting the four by four array, then
	 * we call the @method startEncOrDec to starting the encryption or decryption process for every 16 bytes we read in. In this
	 * way, we are encoding each block (four by four int array) at a time, so say in the input file we have 2 lines with 32
	 * characters in there, then, then the for loop will call the @method startEncOrDec two times, as there will be exactly
	 * two four by four int array or simply two blocks of plain text message.
	*/
	abstract public void prepareToEncOrDec();
}