import json
import time

class CardBackupTool:
    def __init__(self, reader):
        self.reader = reader

    def full_backup(self, path):
        backup_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "card_type": "Unknown",  # You can enhance this by reading card info
            "atr": self.reader.connection.getATR() if self.reader.connection else None,
            "records": {},
            "applications": [],
        }

        # Example: reading some records
        for i in range(1, 6):  # Read first 5 records
            try:
                apdu = [0x00, 0xB2, i, 0x0C, 0x00]
                data, sw1, sw2 = self.reader.transmit(apdu)
                if sw1 == 0x90 and sw2 == 0x00:
                    backup_data["records"][f"record_{i}"] = data
            except Exception as e:
                print(f"Could not read record {i}: {e}")

        with open(path, 'w') as f:
            json.dump(backup_data, f, indent=2, default=list)

        return backup_data

    def restore_from_backup(self, path):
        with open(path, 'r') as f:
            backup_data = json.load(f)

        # Restore logic would go here. This is highly dependent on the card
        # and the data to be written. For now, we'll just simulate.
        print("Restoring from backup... (simulation)")
        for record, data in backup_data.get("records", {}).items():
            print(f"  - Restoring {record} with data: {data}")
            # In a real scenario, you would send APDU commands to write this data.

        return True
