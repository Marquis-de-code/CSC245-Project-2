import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.text.Normalizer;

/*
 * 02/25/2022 AMM: Approval to work bug PR2-ERR01-01 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-ERR01-01).
 *                 All parts of mitigation are tagged with (PR2-ERR01-01-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 * 02/25/2022 AMM: Approval to work bug PR2-ERR01-02 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-ERR01-02).
 *                 All parts of mitigation are tagged with (PR2-ERR01-02-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 * 02/25/2022 AMM: Approval to work bug PR2-IDS01-01 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-IDS01-01).
 *                 All parts of mitigation are tagged with (PR2-IDS01-01-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 * 02/25/2022 AMM: Approval to work bug PR2-IDS01-02 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-IDS01-02).
 *                 All parts of mitigation are tagged with (PR2-IDS01-02-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 * 02/25/2022 AMM: Approval to work bug PR2-FIO16-01 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-FIO16-01).
 *                 All parts of mitigation are tagged with (PR2-FIO16-01-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 * 02/25/2022 AMM: Approval to work bug PR2-IDS50-01 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-IDS50-01).
 *                 All parts of mitigation are tagged with (PR2-IDS50-01-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 * 02/25/2022 AMM: Approval to work bug PR2-IDS51-01 granted.
 *                 All instances of bug are tagged with Bug-ID (PR2-IDS51-01).
 *                 All parts of mitigation are tagged with (PR2-IDS51-01-M#) where # represents an
 *                     incrementing integer for parts of the mitigation
 *                 Status: Open
 */

public class CSC245_Project2 {

  public static void main(String[] args) {
    /* Failure to Normalize Program Argument Before Validation (PR2-IDS01-01)
       Demonstrated by loading the program argument [\U+0066] and uncommenting the print
       statement below, executing the program, and observing the output*/
    String filename = args[0];
//    System.out.println(String.valueOf(filename).equals("\u0041\u0301"));

    BufferedReader inputStream = null;

    String fileLine;
    try {
      /* Failure to Canonicalize Path Before Validation (PR2-FIO16-01)
         Demonstrated by loading .. as a program argument, uncommenting the print statement below,
          and executing the program.

         Failure to Enforce Conservative File Naming Conventions (PR2-IDS50-01)
         Demonstrated by loading program argument --&@, executing the program, and observing the
         output */
//      System.out.println(filename);
      inputStream = new BufferedReader(new FileReader(filename));


      System.out.println("Email Addresses:");
      // Read one Line using BufferedReader
      while ((fileLine = inputStream.readLine()) != null) {
        /* Failure to Normalize File Contents Before Validation PR2-IDS01-02
           Demonstrated by uncommenting the print statement below, executing the program, and
           observing the output.

           Failure to Properly Encode or Escape Output of File Contents (PR2-IDS51-01)
           Demonstrated by loading program argument Email_addresses_20210205.txt, executing the
           program, and observing the results*/
        System.out.println(fileLine);
        System.out.println(String.valueOf(fileLine).equals("\u00f1"));
      }
    } catch (IOException io) {
      /* Exposed Sensitive File System Information General IO Exceptions (PR2-ERR01-01)
         Demonstrated by loading asdf.pl as a program argument, executing the program, and
         observing the output */
      System.out.println("File IO exception" + io.getMessage());
    } finally {
      // Need another catch for closing the streams
      try {
        // Demonstrates bug PR2-ERR01-02 by triggering the catch block containing it
//        throw new IOException();
        if (inputStream != null) {
          inputStream.close();
        }
      } catch (IOException io) {
        /* Exposed Failure to Close File Through IO Exceptions (PR2-ERR01-02)
           Demonstrated by uncommenting the [throw new IOException();] statement in the try block
           directly above and commenting out the if block inside that try block, executing the
           program, and observing the output */
        System.out.println("Issue closing the Files" + io.getMessage());
      }
    }
  }
}
