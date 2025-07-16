from smartcard.System import readers
from smartcard.util import toHexString

class CardReader:
    def __init__(self):
        self.reader = None
        self.connection = None

    def list_readers(self):
        return readers()

    def connect(self, reader_index):
        if self.connection:
            self.disconnect()

        self.reader = readers()[reader_index]
        self.connection = self.reader.createConnection()
        self.connection.connect()
        return self.connection.getATR()

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None
            self.reader = None

    def transmit(self, apdu):
        if not self.connection:
            raise Exception("Not connected to a card reader.")

        data, sw1, sw2 = self.connection.transmit(apdu)
        return data, sw1, sw2
