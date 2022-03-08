import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.Normalizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * 02/25/2022 AMM: Approval to work bug PR2-ERR01-01 granted.
 *                 Bug Tag:        (PR2-ERR01-01)
 *                 Mitigation Tag: (PR2-ERR01-01-M)
 *                 CERT code:      ERR01-J
 *                 Status:         Mitigated
 * 02/25/2022 AMM: Approval to work bug PR2-ERR01-02 granted.
 *                 Bug Tag:        (PR2-ERR01-02)
 *                 Mitigation Tag: (PR2-ERR01-02-M)
 *                 CERT code:      ERR01-J
 *                 Status:         Mitigated
 * 02/25/2022 AMM: Approval to work bug PR2-IDS01-01 granted.
 *                 Bug Tag:        (PR2-IDS01-01)
 *                 Mitigation Tag: (PR2-IDS01-01-M)
 *                 CERT code:      IDS01-J
 *                 Status:         Mitigated
 * 02/25/2022 AMM: Approval to work bug PR2-IDS01-02 granted.
 *                 Bug Tag:        (PR2-IDS01-02)
 *                 Mitigation Tag: (PR2-IDS01-02-M)
 *                 CERT code:      IDS01-J
 *                 Status:         Mitigated
 * 02/25/2022 AMM: Approval to work bug PR2-FIO16-01 granted.
 *                 Bug Tag:        (PR2-FIO16-01)
 *                 Mitigation Tag: (PR2-FIO16-01-M)
 *                 CERT code:      FIO16-J
 *                 Status:         Mitigated
 * 02/25/2022 AMM: Approval to work bug PR2-IDS50-01 granted.
 *                 Bug Tag:        (PR2-IDS50-01)
 *                 Mitigation Tag: (PR2-IDS50-01-M)
 *                 CERT code:      IDS50-J
 *                 Status:         Mitigated
 * 02/25/2022 AMM: Approval to work bug PR2-IDS51-01 granted.
 *                 Bug Tag:        (PR2-IDS51-01)
 *                 Mitigation Tag: (PR2-IDS51-01-M)
 *                 CERT code:      IDS51-J
 *                 Status:         Mitigated
 */

public class CSC245_Project2 {

  public static void main(String[] args) {
    start(args);   // Triggers main program execution
//    pr2err0101mTest();  // Uncomment to test mitigation (PR2-ERR01-01-M)
//    pr2err0102mTest();  // Uncomment to test mitigation (PR2-ERR01-02-M)
//    pr2ids0101mTest();  // Uncomment to test mitigation (PR2-IDS01-01-M)
//    pr2ids0102mTest();  // Uncomment to test mitigation (PR2-IDS01-02-M)
//    pr2fio1601mTest();  // Uncomment to test mitigation (PR2-FIO16-01-M)
//    pr2ids5001mTest();  // Uncomment to test mitigation (PR2-IDS50-01-M)
//    pr2ids5101mTest();  // Uncomment to test mitigation (PR2-IDS51-01-M)
  }

  /**
   * Hosts the core of the program. It inputs a program argument meant to represent a filename
   * within the secure, whitelisted directory and prints its safely encoded contents to the
   * screen. This only occurs after the filename, path, and output have been securely validated
   * to ensure the minimization of vulnerabilities.
   * @param args A string array representing the program arguments. The first element (0th index)
   *             should contain a string representing a filename within the secure, whitelisted
   *             directory
   */
  private static void start(String[] args) {
    /* Bug:       (PR2-IDS01-01) Failure to Normalize Program Argument Before Validation
     * Mit Code:  (PR2-IDS01-01)
     * Status:    Mitigated
     * Tests:     Run pr2ids0101mTest method in the main method
     * Code Desc: Normalizes the filename into a decomposed form before removing all
     *            non-alphanumeric characters except for periods (.), hyphens (-), and underscores
     *            (_) */
    String filename = normalizeAndSanitizeFilename(args[0]);

    /* Bug:       (PR2-IDS50-01) Failure to Enforce Conservative File Naming Conventions
     * Mit Code:  (PR2-IDS01-01-M)
     * Status:    Mitigated
     * Tests:     Run pr2ids5001mTest method in the main method
     * Code Desc: Validate that the filename adheres to the conservative naming conventions
     *            described in the validateFilename method */
    if (validateFilename(filename)) {
      // Declare a BufferedReader that will act as an input stream to read a file's contents
      BufferedReader inputStream = null;

      try {
        /* Bug Code:  (PR2-FIO16-01) Failure to Canonicalize Path Before Validation
         * Mit Code:  (PR2-FIO16-01-M)
         * Status:    Mitigated
         * Tests:     Run pr2fio1601mTest method in the main method
         * Code Desc: Gets the result of adding the filename to the whitelisted path and
         *            canonicalizing it. It then validates that the constructed canonicalized
         *            path points to a file within the whitelisted directory */
        String filePath = getCanonicalPath(filename);
        if (validateFilePath(filePath)) {
          // Once the file path has been validated, print the file's contents to the console.
          inputStream = new BufferedReader(new FileReader(filePath));
          printFileContents(inputStream);
        } else {
          // Canonicalized file path failed validation
          System.out.println("Invalid file");
        }
      } catch (IOException io) {
        /* Bug:       (PR2-ERR01-01) Exposed Sensitive File System Information General IO Exceptions
         * Mit Code:  (PR2-ERR01-01-M)
         * Status:    Mitigated
         * Tests:     Run pr2err0101mTest method in the main method
         * Code Desc: Exception occurs either during canonicalization of the provided path,
         *            during validation of the provided path, or when trying to find, open, or read
         *            the file pointed to by the canonicalized path. */
        System.out.println("Invalid file");
      } finally {
        // Try to close the inputStream Buffered Reader
        closeStream(inputStream);
      }
    } else {
      // Filename failed validation
      System.out.println("Invalid file");
    }

  }

  /**
   * Normalizes a string that is meant to represent a file name and replaces all characters that
   * are not alphanumeric, an underscore (_), a period (.), or a hyphen (-) as those are the only
   * characters allowed in the conservative file naming convention.
   * <p>This is the main implementation of mitigation (PR2-IDS01-01-M) in compliance with CERT code
   * IDS01-J: Normalize strings before validating them </p>
   * @param filename A string that is representative of the name of a file in the whitelisted
   *                 directory
   * @return The string representing the filename after it has been normalized and sanitized of
   * all non-allowed characters.
   */
  private static String normalizeAndSanitizeFilename(String filename) {
    filename = Normalizer.normalize(filename, Normalizer.Form.NFD);
    return filename.replaceAll("[^A-Za-z0-9_.-]", "");
  }

  /**
   * Validates that a filename does not contain undesirable character sequences as according to
   * the conservative file naming standard established below:
   * <p>File names must be 255 characters long or less to be valid. To be valid,
   * they must match the below regex which has the following requirements: filenames must be at
   * least two characters long. The first character must be alphanumeric or an underscore (_).
   * Any subsequent characters may be alphanumeric, an underscore(_), a period (.), or a hyphen
   * (-). Periods and hyphens may not appear more than one time in a row. Finally, it will
   * enforce that the final character of a filename be alphanumeric or an underscore (_).
   * <p>This is the main implementation of mitigation (PR2-IDS50-01-M) in compliance with CERT
   * code IDS50-J: Use conservative file naming conventions</p>
   * @param filename A String representing the name of the file to be validated
   * @return <code>true</code> if the filename is safe and doesn't contain unsafe character
   * sequences. Otherwise, it will return <code>false</code> if the provided filename does contain
   * unsafe character sequences
   */
  private static boolean validateFilename(String filename) {

    if (filename.length() < 255) {
      Pattern pattern = Pattern.compile("^[A-za-z0-9_](([A-Za-z0-9_])*|([A-Za-z0-9_]+[.-]))" +
          "*[A-Za-z0-9_]$");
      // Test the filename against the above pattern and return the results
      Matcher matcher = pattern.matcher(filename);
      return matcher.matches();
    } else {
      return false;
    }
  }

  /**
   * Constructs and returns the canonical path of a filename when placed relative to the secure,
   * whitelisted directory. A canonical path is the simplest equivalent way to construct the
   * absolute path of a file or directory.
   * <p>This is one of two parts of the implementation of mitigation (PR2-IDS50-01-M) in
   * compliance with CERT code FIO16-J: Use conservative file naming conventions</p>
   * @param filename A string representing the name of a file in the whitelisted
   *                 Project-2-Resources directory
   * @return A string representing the canonicalized path of the provided file name in the
   * Project-2-Resources directory.
   * @throws IOException If an IO error occurs then it is from the getCanonicalPath method
   *                     suffering an IO error while trying to query the filesystem.
   */
  private static String getCanonicalPath(String filename) throws IOException {
    String path = System.getenv("Project2WhitelistedPath");
    return new File(path + File.separator + filename).getCanonicalPath();
  }

  /**
   * Validates that a canonicalized path points to a file within the secure whitelisted
   * directory.
   * <p>This is one of two parts of the implementation of mitigation (PR2-FIO16-01-M) in
   * compliance with CERT code FIO16-J: Canonicalize path names before validating them</p>
   * @param filePath A string representing a canonicalized file path
   * @return A boolean representing whether the provided canonicalized file path points to a file
   * in the whitelisted directory (<code>true</code>) or not (<code>false</code>)
   * @throws IOException IO exceptions may occur when using the <code>File.getCanonicalPath()
   *                     </code> method due to the method possibly making queries to the filesystem.
   */
  private static boolean validateFilePath(String filePath) throws IOException {
    // Get the path to the secure whitelisted directory.
    String whitelistedPath = System.getenv("Project2WhitelistedPath");
    // Compare whitelisted path against parent directory of provided file path
    if (whitelistedPath.equals(new File(filePath).getParentFile().getCanonicalPath())) {
      // Compare provided file path against file paths of children files in whitelisted directory
      String[] childPaths = new File(whitelistedPath).list();
      if (childPaths != null) {
        for (String childPath : childPaths) {
          childPath = new File(whitelistedPath + File.separator + childPath).getCanonicalPath();
          // If one of the child paths matches, then the canonicalized path has been validated.
          if (childPath.equals(filePath)) {
            return true;
          }
        }
      }
    }
    /* Path either didn't have the whitelisted directory as the parent directory or the file was
     * not actually a file within that directory */
    return false;
  }

  /**
   * Prints out the normalized, escaped, encoded, and sanitized input from a BufferedReader
   * representing a file's contents.
   * @param inputStream A BufferedReader reading from a file
   * @throws IOException <code>BufferedReader.readLine()</code> may throw a <code>IOException</code>
   */
  private static void printFileContents(BufferedReader inputStream) throws IOException {
    System.out.println("File Contents:");
    // The file line by line using the BufferedReader
    String fileLine;
    while ((fileLine = inputStream.readLine()) != null) {
      /* Bug:       (PR2-IDS01-02) Failure to Normalize File Contents Before Validation
       * Mit Code:  (PR2-ERR01-02-M)
       * Status:    Mitigated
       * Tests:     Run pr2ids0102mTest method in the main method */
      fileLine = Normalizer.normalize(fileLine, Normalizer.Form.NFKC);

      /* Bug:       (PR2-IDS51-01) Failure to Properly Encode or Escape Output of File Contents
       * Mit Code:  (PR2-IDS51-01-M)
       * Status:    Mitigated
       * Tests:     Run pr2ids5101mTest method in the main method
       * Code Desc: Encodes non-alphanumeric characters into their HTML safe versions*/
      fileLine = HTMLEntityEncode(fileLine);
      if (validateOutput(fileLine)) {
        System.out.println(fileLine);
      }
    }
  }

  /**
   * Encodes unsafe characters (non-alphanumeric or non-whitespace characters) into an HTML safe
   * format
   * @param input A string representing a line from a file
   * @return A string representing the same line from the file with its unsafe characters encoded
   * in an HTML safe format
   */
  private static String HTMLEntityEncode(String input) {
    /* This whole method is taken from Carnegie Mellon University's Software Engineering
     * Institute's compliant solution for CERT code IDS51-J Properly encode or escape output. It
     * will encode unsafe characters (non-alphanumeric or non-whitespace characters) into an HTML
     * safe format
     * Mohindra, Dhruv, et al. “IDS51-J. Properly Encode or Escape Output.” Confluence, Carnegie
     * Mellon University Software Engineering Institute,
     * https://wiki.sei.cmu.edu/confluence/display/java/IDS51-J.+Properly+encode+or+escape+output */
    StringBuffer sb = new StringBuffer();

    for (int i = 0; i < input.length(); i++) {
      char ch = input.charAt(i);
      if (Character.isLetterOrDigit(ch) || Character.isWhitespace(ch)) {
        sb.append(ch);
      } else {
        sb.append("&#" + (int)ch + ";");
      }
    }
    return sb.toString();
    // End of attributed code
  }

  /**
   * Validates that the output has been properly encoded to HTML so that the only characters
   * present are either alphanumeric or take the form of &#charCode;
   * @param output A string representing potential output
   * @return A boolean representing whether the provided string has passed validation.
   * <code>true</code> if the string passed validation, <code>false</code> if it did not.
   */
  private static Boolean validateOutput(String output) {
    // Regex matches only alphanumeric characters/character sequences that take the form &#charCode;
    Pattern pattern = Pattern.compile("([A-Za-z0-9]+|(&#[0-9]+;)+)+");
    Matcher matcher = pattern.matcher(output);

    // Return whether the string meets the required form outlined above
    return matcher.matches();
  }

  /**
   * Close <code>BufferedReader</code> acting as the input stream. Log IO exception if it fails
   * to close the input stream.
   * @param inputStream A BufferedReader being used as a stream to receive input on.
   */
  private static void closeStream(BufferedReader inputStream) {
    // Try to close the Buffered Reader, log the exception if it fails
    try {
      // Prevent null pointer exception with null check and close the stream if it's not already.
      if (inputStream != null) {
        inputStream.close();
      }
    } catch (IOException io) {
      /* Bug:       (PR2-ERR01-01) Exposed Sensitive File System Information General IO Exceptions
       * CERT code: ERR01-J. Do not allow exceptions to expose sensitive information
       * Status:    Closed
       * Tests:     Uncomment the throw new IOException() at the top of the try block directly
       *            above and comment out the rest of the try block; Output should read
       *            "Program finished" */
      System.out.println("Program finished");  // In here to prevent empty catch block
      // Securely log exception...
    }
  }

  // TEST METHODS BELOW!

  /**
   * Tests that the print statement used in mitigation PR2-ERR01-01-M achieves the desired
   * outcome of not leaking any sensitive information.
   */
  private static void pr2err0101mTest() {
    /* Simulate try-catch-finally blocks and cause intentional exception to see the result of
     * the print statement */
    try {
      // Try to find, open, and read file
      throw new IOException();    // Simulate IOException
    } catch (IOException io) {
      System.out.println("Invalid file");   // Replicate code for catching exception
    }

    // Print that the test was passed as no sensitive information was leaked
    System.out.println("PR2-ERR01-01-M Test: passed");
  }

  /**
   * Tests that the print statement used in mitigation PR2-ERR01-02-M achieves the desired
   * outcome of not leaking any sensitive information.
   */
  private static void pr2err0102mTest() {
    /* Simulate try-catch blocks and cause intentional exception to see the result of
     * the print statement */
    try {
      // Try to close the streams
      throw new IOException();    // Simulate IOException
    } catch (IOException io) {
      System.out.println("Program finished");   // Replicate code for catching exception
      // Securely log exception...
    }

    // Print that the test was passed as no sensitive information was leaked
    System.out.println("PR2-ERR01-02-M Test: passed");
  }

  /**
   * Tests that the statements used in mitigation PR2-IDS01-01-M achieve the desired outcome of
   * stripping all non-alphanumeric characters except periods (.), underscores (_), and hyphens (-)
   * while attempting to salvage as many of the "bad characters" as it can by decomposing them
   * into a normalized form before stripping all characters except those mentioned above.
   */
  private static void pr2ids0101mTest() {
    String[] filenames = {
        "Áslt",
        "ñÅö",
        "ḱṷṓ",
        "bad-File-Name!",
        "Still%Bad",
        "Wo&^rs3+=filen{}[]|\\$@*?,/ame",
        "\u0041\u0301"
    };
    String[] expectedOutput = {
        "Aslt",
        "nAo",
        "kuo",
        "bad-File-Name",
        "StillBad",
        "Wors3filename",
        "A"
    };

    /* Compare the normalized and sanitized output of the above filenames against their expected
       outputs */
    boolean testFailed = false;
    int i = 0;
    while (i < filenames.length && !testFailed) {
      if (!expectedOutput[i].equals(normalizeAndSanitizeFilename(filenames[i]))) {
        testFailed = true;
      }
      i++;
    }

    // Print result of test
    System.out.print("PR2-IDS01-01-M Test: ");
    if (testFailed) {
      System.out.println("failed");
    } else {
      System.out.println("passed");
    }
  }

  /**
   * Tests that the method of normalization used in mitigation PR2-IDS01-02-M was effective and
   * achieved desired output.
   */
  private static void pr2ids0102mTest() {
    // Character sequences that causes non-normalized text to register as different.
    String[] fileLines = {"\u006e\u0303", "ñ", "ñ", "\u00f1", "-.!()"};
    // The expected output of character sequences if normalization achieves desired outcome
    String[] expectedOutput = {"\u00f1", "\u00f1", "\u00f1", "\u00f1", "\u002d\u002e\u0021\u0028" +
        "\u0029"};

    // Validate each string representing a file line against its expected and desired output
    boolean testFailed = false;
    int i = 0;
    while (i < fileLines.length && !testFailed) {
      if (!Normalizer.normalize(fileLines[i], Normalizer.Form.NFKC).equals(expectedOutput[i])) {
        testFailed = true;
      }
      i++;
    }

    // Print the results of the test
    System.out.print("PR2-IDS01-02-M Test: ");
    if (testFailed) {
      System.out.println("failed");
    } else {
      System.out.println("passed");
    }
  }

  /**
   * Tests that canonicalization and validation used in mitigation PR2-FIO16-01-M achieve the
   * desired outcome of ensuring that all validated file paths point to a file that is within the
   * secure, whitelisted directory.
   */
  private static void pr2fio1601mTest() {
    String[] filenames = {"Email_addresses_20210205.txt", "goodFileNameButNotReal", "%bad!file" +
        "^name", ".." + File.separator + "README.md", ".." + File.separator +
        "Email_addresses_20210205.txt", "\\\\\\\\\\\\\\"};
    boolean[] expectedOutput = {true, false, false, false, false, false, false};


    // Perform canonicalization and file path validation on file name examples and
    // Validate each string representing a file line against its expected and desired output
    boolean testFailed = false;
    int i = 0;
    while (i < filenames.length && !testFailed) {
      boolean pathValid;
      try {
        String filePath = getCanonicalPath(filenames[i]);
        pathValid = validateFilePath(filePath);
      } catch (IOException io) {
        // Normally print that file is invalid. For test just treat this as a false result
        pathValid = false;
      }
      if (pathValid != expectedOutput[i]) {
        testFailed = true;
      }
      i++;
    }

    // Print the results of the test
    System.out.print("PR2-FIO16-01-M Test: ");
    if (testFailed) {
      System.out.println("failed");
    } else {
      System.out.println("passed");
    }
  }

  /**
   * Tests that the statements used in mitigation PR2-IDS50-01-M achieve the desired outcome of
   * enforcing that filenames require a certain format before they are operated upon. The
   * requirements of a file name are that they must be 255 characters or smaller to be valid.
   * They must match the below regex which has the following requirements:
   * filenames must be at least two characters long. The first character must be alphanumeric or an
   * underscore (_). Any subsequent characters may be alphanumeric, an underscore(_), a period (.),
   * or a hyphen (-). Periods and hyphens may not appear more than one time in a row. Finally, it
   * will enforce that the final character of a filename be alphanumeric or an underscore (-).
   */
  private static void pr2ids5001mTest() {
    // Strings to test the file name validation against
    String[] filenames = {"test-file", "test.file", "testFile", "-test-file", ".test-file",
        "test-file.",  "test-file-", "test..file", "test--file", "test!file", "test^file",
        "\ttestFile", "(testfile", "&%^@terset.pl", "", "Á",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    // Expected result of the validation of each string the array above
    Boolean[] assertions = {true, true, true, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false};

    // Validate each string as a filename and compare against the expected result.
    boolean testFailed = false;
    int i = 0;
    while (i < filenames.length && !testFailed) {
      if (validateFilename(filenames[i]) != assertions[i]) {
        testFailed = true;
      }
      i++;
    }

    // Print the results of the test
    System.out.print("PR2-IDS50-01-M Test: ");
    if (testFailed) {
      System.out.println("failed");
    } else {
      System.out.println("passed");
    }
  }

  /**
   * Tests that the statements used in mitigation PR2-IDS51-01-M achieve the desired outcome of
   * encoding all non-alphanumeric characters into their HTML safe counterparts. Tested by taking
   * input with known proper encoding and comparing it against mitigation PR2-IDS51-01-M's output
   */
  private static void pr2ids5101mTest() {
    String[] fileLines = {"!@#$%^&*()-=;:'\",.<>/?|\\[]{}", "\uD835\uDCF7\uD835\uDD93",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiumod tempor incididunt",
        "<script>Malicious-JavaScript-Code<\\script>"};
    String[] expectedOutput = {"&#33;&#64;&#35;&#36;&#37;&#94;&#38;&#42;&#40;&#41;&#45;&#61;&#59;" +
        "&#58;&#39;&#34;&#44;&#46;&#60;&#62;&#47;&#63;&#124;&#92;&#91;&#93;&#123;&#125;", "nn",
        "Lorem ipsum dolor sit amet&#44; consectetur adipiscing elit&#44; sed do eiumod tempor " +
        "incididunt", "&#60;script&#62;Malicious&#45;JavaScript&#45;Code&#60;&#92;script&#62;"
    };

    // Validate that each string gets normalized and encoded to its expected output
    boolean testFailed = false;
    int i = 0;
    while (i < fileLines.length && !testFailed) {
      String fileLine = HTMLEntityEncode(Normalizer.normalize(fileLines[i], Normalizer.Form.NFKC));
      if (!fileLine.equals(expectedOutput[i])) {
        testFailed = true;
      }
      i++;
    }

    // Print the results of the test
    System.out.print("PR2-IDS51-01-M Test: ");
    if (testFailed) {
      System.out.println("failed");
    } else {
      System.out.println("passed");
    }
  }
}
