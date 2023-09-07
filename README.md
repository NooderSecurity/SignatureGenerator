# Malware Signature Toolset

This toolset provides utilities to generate malware signatures and to check files against those signatures for potential malware matches.

## Components:

1. **SignatureGenerator:** Generates malware signatures from samples in a specified directory.
2. **SignatureChecker:** Checks a file or files within a ZIP archive against a database of malware signatures.

## Usage:

### SignatureGenerator:

Generates signatures for each file in a given directory and its sub-directories.

`Usage: SignatureGenerator <directory_path> <virus_type>`

- `directory_path`: Path to the directory containing malware samples.
- `virus_type`: Type of virus/malware (e.g., Trojan, Worm, Ransomware). This is used to categorize the generated signatures.

The generated signatures are saved to `signatures.json`.

### SignatureChecker:

Checks a file or ZIP archive against known malware signatures.

`Usage: SignatureChecker <target_file_path>`

- `target_file_path`: Path to the file or ZIP archive to be checked.

The program will display potential malware matches found in the provided file or ZIP archive.

## Notes:

- The generated signatures are based on SHA256 hashes of segments of the binary data. 
- This toolset is for educational purposes. Real-world malware often employs various evasion techniques. If you're planning to use this in a professional context, consider integrating more advanced features.
