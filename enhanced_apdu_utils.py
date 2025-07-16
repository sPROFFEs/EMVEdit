# Enhanced APDU utilities for EMV Professional Tool
import struct

EMV_COMMANDS = {
    "SELECT_PSE": "00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31",
    "SELECT_PPSE": "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31",
    "GET_PROCESSING_OPTIONS": "80 A8 00 00 02 83 00",
    "READ_RECORD_1": "00 B2 01 0C 00",
    "READ_RECORD_2": "00 B2 02 0C 00",
    "READ_RECORD_3": "00 B2 03 0C 00",
    "READ_RECORD_4": "00 B2 04 0C 00",
    "READ_RECORD_5": "00 B2 05 0C 00",
    # Comandos adicionales profesionales
    "SELECT_MF": "00 A4 00 00 02 3F 00",
    "GET_CHALLENGE": "00 84 00 00 08",
    "VERIFY_PIN": "00 20 00 80 08",
    "GET_DATA": "80 CA 9F 13 00",
    "COMPUTE_CRYPTOGRAPHIC_CHECKSUM": "80 2A 8E 80 04",
    "INTERNAL_AUTHENTICATE": "00 88 00 00 10",
    "EXTERNAL_AUTHENTICATE": "00 82 00 00 10",
    "GENERATE_AC": "80 AE 80 00 0D",
}

# Tags EMV extendidos para análisis profesional
EMV_TAGS = {
    # Template tags
    0x6F: "File Control Information (FCI) Template",
    0x61: "Application Template",
    0x70: "EMV Proprietary Template",
    0x77: "Response Message Template Format 2",
    0x80: "Response Message Template Format 1",
    0xA5: "File Control Information (FCI) Proprietary Template",
    
    # Data Object tags
    0x4F: "Application Identifier (AID)",
    0x50: "Application Label",
    0x57: "Track 2 Equivalent Data",
    0x5A: "Application Primary Account Number (PAN)",
    0x5F20: "Cardholder Name",
    0x5F24: "Application Expiration Date",
    0x5F25: "Application Effective Date",
    0x5F28: "Issuer Country Code",
    0x5F2A: "Transaction Currency Code",
    0x5F2D: "Language Preference",
    0x5F30: "Service Code",
    0x5F34: "Application Primary Account Number (PAN) Sequence Number",
    0x5F36: "Transaction Currency Exponent",
    0x5F50: "Issuer URL",
    0x5F53: "International Bank Account Number (IBAN)",
    0x5F54: "Bank Identifier Code (BIC)",
    0x5F55: "Issuer Country Code (alpha2 format)",
    0x5F56: "Issuer Country Code (alpha3 format)",
    
    # EMV specific tags
    0x82: "Application Interchange Profile",
    0x83: "Command Template",
    0x84: "Dedicated File (DF) Name",
    0x87: "Application Priority Indicator",
    0x88: "Short File Identifier (SFI)",
    0x8A: "Authorisation Response Code",
    0x8C: "Card Risk Management Data Object List 1 (CDOL1)",
    0x8D: "Card Risk Management Data Object List 2 (CDOL2)",
    0x8E: "Cardholder Verification Method (CVM) List",
    0x8F: "Certification Authority Public Key Index",
    0x90: "Issuer Public Key Certificate",
    0x91: "Issuer Authentication Data",
    0x92: "Issuer Public Key Remainder",
    0x93: "Signed Static Application Data",
    0x94: "Application File Locator (AFL)",
    0x95: "Terminal Verification Results",
    0x97: "Transaction Certificate Data Object List (TDOL)",
    0x98: "Transaction Certificate (TC) Hash Value",
    0x99: "Transaction Personal Identification Number (PIN) Data",
    0x9A: "Transaction Date",
    0x9B: "Transaction Status Information",
    0x9C: "Transaction Type",
    0x9D: "Directory Definition File (DDF) Name",
    
    # EMV proprietary tags (9F series)
    0x9F01: "Acquirer Identifier",
    0x9F02: "Amount, Authorised (Numeric)",
    0x9F03: "Amount, Other (Numeric)",
    0x9F04: "Amount, Other (Binary)",
    0x9F05: "Application Discretionary Data",
    0x9F06: "Application Identifier (AID) - terminal",
    0x9F07: "Application Usage Control",
    0x9F08: "Application Version Number",
    0x9F09: "Application Version Number",
    0x9F0B: "Cardholder Name Extended",
    0x9F0D: "Issuer Action Code - Default",
    0x9F0E: "Issuer Action Code - Denial",
    0x9F0F: "Issuer Action Code - Online",
    0x9F10: "Issuer Application Data",
    0x9F11: "Issuer Code Table Index",
    0x9F12: "Application Preferred Name",
    0x9F13: "Last Online Application Transaction Counter (ATC) Register",
    0x9F14: "Lower Consecutive Offline Limit",
    0x9F15: "Merchant Category Code",
    0x9F16: "Merchant Identifier",
    0x9F17: "Personal Identification Number (PIN) Try Counter",
    0x9F18: "Issuer Script Identifier",
    0x9F1A: "Terminal Country Code",
    0x9F1B: "Terminal Floor Limit",
    0x9F1C: "Terminal Identification",
    0x9F1D: "Terminal Risk Management Data",
    0x9F1E: "Interface Device (IFD) Serial Number",
    0x9F1F: "Track 1 Discretionary Data",
    0x9F20: "Track 2 Discretionary Data",
    0x9F21: "Transaction Time",
    0x9F22: "Certification Authority Public Key Index",
    0x9F23: "Upper Consecutive Offline Limit",
    0x9F26: "Application Cryptogram",
    0x9F27: "Cryptogram Information Data",
    0x9F2D: "Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate",
    0x9F2E: "Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent",
    0x9F2F: "Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder",
    0x9F32: "Issuer Public Key Exponent",
    0x9F33: "Terminal Capabilities",
    0x9F34: "Cardholder Verification Method (CVM) Results",
    0x9F35: "Terminal Type",
    0x9F36: "Application Transaction Counter (ATC)",
    0x9F37: "Unpredictable Number",
    0x9F38: "Processing Options Data Object List (PDOL)",
    0x9F39: "Point-of-Service (POS) Entry Mode",
    0x9F3A: "Amount, Reference Currency",
    0x9F3B: "Application Reference Currency",
    0x9F3C: "Transaction Reference Currency Code",
    0x9F3D: "Transaction Reference Currency Exponent",
    0x9F40: "Additional Terminal Capabilities",
    0x9F41: "Transaction Sequence Counter",
    0x9F42: "Application Currency Code",
    0x9F43: "Application Reference Currency Exponent",
    0x9F44: "Application Currency Exponent",
    0x9F45: "Data Authentication Code",
    0x9F46: "Integrated Circuit Card (ICC) Public Key Certificate",
    0x9F47: "Integrated Circuit Card (ICC) Public Key Exponent",
    0x9F48: "Integrated Circuit Card (ICC) Public Key Remainder",
    0x9F49: "Dynamic Data Authentication Data Object List (DDOL)",
    0x9F4A: "Static Data Authentication Tag List",
    0x9F4B: "Signed Dynamic Application Data",
    0x9F4C: "ICC Dynamic Number",
    0x9F4D: "Log Entry",
    0x9F4E: "Merchant Name and Location",
    0x9F4F: "Log Format",
}

# Extended status word interpretations
SW_CODES = {
    # Success
    (0x90, 0x00): "Success",
    (0x61, None): "SW2 indicates the number of response bytes still available",
    
    # Warning conditions
    (0x62, 0x00): "No information given (NV-Ram not changed)",
    (0x62, 0x01): "NV-Ram not changed 1",
    (0x62, 0x81): "Part of returned data may be corrupted",
    (0x62, 0x82): "End of file/record reached before reading Le bytes",
    (0x62, 0x83): "Selected file invalidated",
    (0x62, 0x84): "Selected file in termination state",
    (0x62, 0x85): "No Secure Messaging keys available within the card",
    (0x62, 0x86): "Reserved",
    (0x62, 0x87): "Reserved",
    (0x62, 0x88): "Reserved",
    (0x62, 0xA2): "Wrong R-MAC",
    (0x62, 0xA4): "Card locked (during reset( ))",
    (0x62, 0xCX): "Counter with value X (command dependent)",
    (0x62, 0xF1): "Wrong C-MAC",
    (0x62, 0xF3): "Internal reset",
    (0x62, 0xF5): "Default agent locked",
    (0x62, 0xF7): "Cardholder locked",
    (0x62, 0xF8): "Basement is current agent",
    (0x62, 0xF9): "CALC Key Set not unblocked",
    
    # Execution errors
    (0x63, 0x00): "No information given (NV-Ram changed)",
    (0x63, 0x81): "File filled up by the last write. Loading/updating is not allowed",
    (0x63, 0x82): "Card key not supported",
    (0x63, 0x83): "Reader key not supported",
    (0x63, 0x84): "Plaintext transmission not supported",
    (0x63, 0x85): "Secured transmission not supported",
    (0x63, 0x86): "Volatile memory is not available",
    (0x63, 0x87): "Non-volatile memory is not available", 
    (0x63, 0x88): "Key number not valid",
    (0x63, 0x89): "Key length is not correct",
    (0x63, 0xC0): "Verify fail, no try left",
    (0x63, 0xC1): "Verify fail, 1 try left",
    (0x63, 0xC2): "Verify fail, 2 tries left",
    (0x63, 0xC3): "Verify fail, 3 tries left",
    (0x63, 0xCX): "Verify fail, X retries left",
    
    # Checking errors
    (0x64, 0x00): "No information given (NV-Ram not changed)",
    (0x64, 0x01): "Command timeout. Immediate response required by the card",
    
    (0x65, 0x00): "No information given",
    (0x65, 0x01): "Write error. Memory failure. There have been problems in writing or reading the EEPROM",
    (0x65, 0x81): "Memory failure",
    
    # Wrong length
    (0x67, 0x00): "Wrong length",
    
    # Functions in CLA not supported
    (0x68, 0x00): "No information given (The request function is not supported by the card)",
    (0x68, 0x81): "Logical channel not supported",
    (0x68, 0x82): "Secure messaging not supported",
    (0x68, 0x83): "Last command of the chain expected",
    (0x68, 0x84): "Command chaining not supported",
    
    # Command not allowed
    (0x69, 0x00): "No information given (Command not allowed)",
    (0x69, 0x81): "Command incompatible with file structure",
    (0x69, 0x82): "Security condition not satisfied",
    (0x69, 0x83): "Authentication method blocked",
    (0x69, 0x84): "Referenced data reversibly blocked (invalidated)",
    (0x69, 0x85): "Conditions of use not satisfied",
    (0x69, 0x86): "Command not allowed (no current EF)",
    (0x69, 0x87): "Expected secure messaging (SM) object missing",
    (0x69, 0x88): "Incorrect secure messaging (SM) data object",
    (0x69, 0x96): "Data must be updated again",
    (0x69, 0xE1): "POL1 of the currently Enabled Profile prevents this action",
    (0x69, 0xF0): "Permission Denied",
    (0x69, 0xF1): "Permission Denied - Missing Privilege",
    
    # Wrong parameter(s) P1-P2
    (0x6A, 0x00): "No information given (Bytes P1 and/or P2 are incorrect)",
    (0x6A, 0x80): "The parameters in the data field are incorrect",
    (0x6A, 0x81): "Function not supported",
    (0x6A, 0x82): "File not found",
    (0x6A, 0x83): "Record not found",
    (0x6A, 0x84): "Not enough memory space in the file",
    (0x6A, 0x85): "Nc inconsistent with TLV structure",
    (0x6A, 0x86): "Incorrect parameters P1-P2",
    (0x6A, 0x87): "Nc inconsistent with parameters P1-P2",
    (0x6A, 0x88): "Referenced data not found",
    (0x6A, 0x89): "File already exists",
    (0x6A, 0x8A): "DF name already exists",
    
    # Wrong parameter(s) P1-P2
    (0x6B, 0x00): "Wrong parameter(s) P1-P2",
    
    # Le field incorrect
    (0x6C, None): "Wrong Le field",
    
    # Instruction code not supported or invalid
    (0x6D, 0x00): "Instruction code not supported or invalid",
    
    # Class not supported
    (0x6E, 0x00): "Class not supported",
    
    # Technical problem
    (0x6F, 0x00): "Internal exception",
}

def format_apdu_response(data, sw1, sw2):
    """Format APDU response with enhanced information"""
    data_hex = ' '.join(f"{b:02X}" for b in data) if data else "No data"
    sw_meaning = interpret_sw_professional(sw1, sw2)
    
    response = f"Response Data: {data_hex}\n"
    response += f"Status Words: {sw1:02X} {sw2:02X}\n"
    response += f"Meaning: {sw_meaning}\n"
    response += f"Data Length: {len(data)} bytes"
    
    return response

def interpret_sw_professional(sw1, sw2):
    """Professional status word interpretation"""
    # Check exact match first
    if (sw1, sw2) in SW_CODES:
        return SW_CODES[(sw1, sw2)]
    
    # Check pattern matches
    if (sw1, None) in SW_CODES:
        base_meaning = SW_CODES[(sw1, None)]
        if sw1 == 0x61:
            return f"{base_meaning} ({sw2} bytes available)"
        elif sw1 == 0x6C:
            return f"{base_meaning} (expected Le = {sw2})"
        else:
            return f"{base_meaning} (SW2 = {sw2:02X})"
    
    # Check special patterns
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        retries = sw2 & 0x0F
        return f"Verify fail, {retries} retries left"
    
    # Unknown status
    return f"Unknown status (SW1={sw1:02X} SW