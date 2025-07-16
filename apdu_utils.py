from enhanced_apdu_utils import EMV_COMMANDS, EMV_TAGS, SW_CODES

def parse_tlv(data):
    """Parses TLV encoded data."""
    tlvs = []
    i = 0
    while i < len(data):
        tag = data[i]
        i += 1
        if (tag & 0x1F) == 0x1F:
            tag = (tag << 8) | data[i]
            i += 1

        length = data[i]
        i += 1
        if length & 0x80:
            len_bytes = length & 0x7F
            length = 0
            for j in range(len_bytes):
                length = (length << 8) | data[i]
                i += 1

        value = data[i:i+length]
        i += length

        subitems = []
        if (tag & 0x20): # Constructed tag
            subitems = parse_tlv(value)

        tlvs.append((tag, length, value, subitems))

    return tlvs

def format_tlv(tlv_data, indent=0):
    """Formats parsed TLV data for display."""
    output = ""
    for tag, length, value, subitems in tlv_data:
        tag_hex = f"{tag:04X}"
        desc = EMV_TAGS.get(tag, "Unknown Tag")
        output += "  " * indent + f"Tag: {tag_hex} ({desc}), Length: {length}\n"
        if subitems:
            output += format_tlv(subitems, indent + 1)
        else:
            output += "  " * (indent + 1) + f"Value: {''.join(f'{b:02X}' for b in value)}\n"
    return output

def format_apdu_response(data, sw1, sw2):
    return f"Data: {toHexString(data)} SW1: {sw1:02X} SW2: {sw2:02X}"
