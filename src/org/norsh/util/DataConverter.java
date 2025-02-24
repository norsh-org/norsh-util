package org.norsh.util;

import java.nio.ByteBuffer;
import java.util.Base64;

/**
 * <p>
 * The {@code DataConverter} class provides utility methods to convert between hex, Base64, and byte array representations. This
 * is useful for encoding and decoding data in various formats commonly used in blockchain and cryptographic applications.
 * </p>
 *
 * <h2>Features:</h2>
 * <ul>
 * <li>Converts between hex, Base64, and byte arrays.</li>
 * <li>Supports normalization of PEM keys.</li>
 * <li>Validates Hex and Base64 formats for input strings.</li>
 * <li>Handles invalid inputs with clear exceptions.</li>
 * </ul>
 *
 * @license NCL-R
 * @author Danthur Lice
 * @since 12/2024
 * @version 1.0
 * @see <a href="https://docs.norsh.org">Norsh Documentation</a>
 */
public class DataConverter {

	/**
	 * Converts a byte array to a hexadecimal string.
	 *
	 * @param byteArray the byte array to convert.
	 * @return a hexadecimal string representation of the byte array, or {@code null} if the input is {@code null}.
	 */
	public static String bytesToHex(byte[] byteArray) {
		if (byteArray == null) {
			return null;
		}

		StringBuilder hexBuilder = new StringBuilder();
		for (byte b : byteArray) {
			hexBuilder.append(String.format("%02x", b)); // Two-digit hexadecimal format
		}
		return hexBuilder.toString();
	}

	/**
	 * Converts a hexadecimal string to a byte array.
	 *
	 * @param hexString the hexadecimal string to convert.
	 * @return a byte array representation of the hexadecimal string.
	 * @throws IllegalArgumentException if the input string is not a valid hexadecimal string.
	 */
	public static byte[] hexToBytes(String hexString) {
		if (hexString == null || hexString.trim().isEmpty()) {
			return null;
		}

		hexString = hexString.trim();
		if (hexString.startsWith("0x")) {
			hexString = hexString.substring(2);
		}

		if (!hexString.matches("[a-fA-F0-9]+")) {
			throw new IllegalArgumentException("Invalid hexadecimal input: " + hexString);
		}

		int len = hexString.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * Converts a byte array to a Base64 string.
	 *
	 * @param byteArray the byte array to convert.
	 * @return a Base64 string representation of the byte array, or {@code null} if the input is {@code null}.
	 */
	public static String bytesToBase64(byte[] byteArray) {
		if (byteArray == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(byteArray);
	}

	/**
	 * Converts a Base64 string to a byte array.
	 *
	 * @param base64String the Base64 string to convert.
	 * @return a byte array representation of the Base64 string.
	 * @throws IllegalArgumentException if the input string is not a valid Base64 string.
	 */
	public static byte[] base64ToBytes(String base64String) {
		if (base64String == null || base64String.isEmpty()) {
			return null;
		}

		try {
			return Base64.getDecoder().decode(base64String);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Invalid Base64 input: " + base64String, e);
		}
	}

	/**
	 * Converts a Base64 string to a hexadecimal string.
	 *
	 * @param base64String the Base64 string to convert.
	 * @return a hexadecimal string representation of the Base64 input.
	 * @throws IllegalArgumentException if the input string is not a valid Base64 string.
	 */
	public static String base64ToHex(String base64String) {
		byte[] bytes = base64ToBytes(base64String);
		return bytesToHex(bytes);
	}

	/**
	 * Converts a hexadecimal string to a Base64 string.
	 *
	 * @param hexString the hexadecimal string to convert.
	 * @return a Base64 string representation of the hexadecimal input.
	 * @throws IllegalArgumentException if the input string is not a valid hexadecimal string.
	 */
	public static String hexToBase64(String hexString) {
		byte[] bytes = hexToBytes(hexString);
		return bytesToBase64(bytes);
	}

	/**
	 * Converts an integer value to a byte array.
	 * <p>
	 * The method uses a {@link ByteBuffer} to allocate memory and encode the integer as a 4-byte array.
	 * </p>
	 *
	 * @param value the integer value to convert.
	 * @return a byte array representation of the integer.
	 */
	public static byte[] intToByteArray(int value) {
		return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
	}

	/**
	 * Converts a long value to a byte array.
	 * <p>
	 * The method uses a {@link ByteBuffer} to allocate memory and encode the long as an 8-byte array.
	 * </p>
	 *
	 * @param value the long value to convert.
	 * @return a byte array representation of the long.
	 */
	public static byte[] longToByteArray(long value) {
		return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
	}

	/**
	 * Converts a double value to a byte array.
	 * <p>
	 * The method uses a {@link ByteBuffer} to allocate memory and encode the double as an 8-byte array.
	 * </p>
	 *
	 * @param value the double value to convert.
	 * @return a byte array representation of the double.
	 */
	public static byte[] doubleToByteArray(double value) {
		return ByteBuffer.allocate(Double.BYTES).putDouble(value).array();
	}

	/**
	 * Decodes a string (either Hexadecimal or Base64) into a byte array.
	 *
	 * <p>
	 * The method first trims the input and normalizes PEM key formatting. Then, it checks the input format:
	 * <ul>
	 * <li>If the input is a valid hexadecimal string, it is decoded to a byte array.</li>
	 * <li>If the input is a valid Base64 string, it is decoded to a byte array.</li>
	 * </ul>
	 * </p>
	 *
	 * @param input the input string to decode.
	 * @return the decoded byte array, or {@code null} if the input is {@code null} or empty.
	 * @throws IllegalArgumentException if the input is not a valid hexadecimal or Base64 string.
	 */
	public static byte[] base64OrHexToBytes(String input) throws IllegalArgumentException {
		if (input == null || input.trim().isEmpty()) {
			return null;
		}

		input = parsePemKey(input);

		if (input.matches("[a-fA-F0-9]+")) {
			return hexToBytes(input);
		}

		if (input.matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")) {
			return base64ToBytes(input);
		}

		throw new IllegalArgumentException("Invalid input: Not a valid Hexadecimal or Base64 string.");
	}

	/**
	 * Validates if the input string is either a valid Base64 or Hexadecimal format.
	 *
	 * @param input the input string to validate.
	 * @return {@code true} if the input is a valid Base64 or Hexadecimal string, {@code false} otherwise.
	 */
	public static boolean isBase64OrHex(String input) {
		if (input == null || input.trim().isEmpty()) {
			return false;
		}

		input = parsePemKey(input);

		return input.matches("[a-fA-F0-9]+") || input.matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
	}

	/**
	 * Normalizes PEM key formats by removing headers, footers, and unnecessary characters.
	 *
	 * <p>
	 * This method ensures safe removal of headers and footers, such as "BEGIN", "END", "PRIVATE", "PUBLIC", and "KEY", without
	 * accidentally altering valid Base64-encoded key data. The spaces and dashes before or after these keywords provide additional
	 * safeguards against unintentional replacements in cases where similar sequences might appear in Base64 strings.
	 * </p>
	 *
	 * @param pemKey the PEM key string to normalize.
	 * @return a cleaned string containing only the key data.
	 */
	public static String parsePemKey(String pemKey) {
		return pemKey.trim().replace("-BEGIN", "").replace("-END", "").replace(" PRIVATE", "").replace(" PUBLIC", "").replace("KEY-", "").replace("-", "").replaceAll("\\s", "");
	}

}
