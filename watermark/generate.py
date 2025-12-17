from hashlib import sha256
import secrets
import struct
from string import ascii_lowercase

netid = "sf647"  # change to your netid


# Put your solution generation code here
def compute_watermark(netid: str) -> bytes:
    # computing sha256 hash
    hash_bytes = sha256(netid.encode(encoding="ascii", errors="ignore")).digest()
    # extracting first 2 bytes for watermark
    watermark = hash_bytes[:2]
    return watermark


def generate_preimage(watermark: bytes) -> bytes:
    # genertae random 6 byte preimage
    preimage_no_watermark = secrets.token_bytes(6)
    # adding watermark with the random 6 byte preimage
    preimage = watermark + preimage_no_watermark
    return preimage


def hash_preimage(preimage: bytes) -> str:
    # hashing the preimage
    hashed_preimage = sha256(preimage).digest()
    # get the first 4 bytes(32 bits)-need to extract the first 28
    hashed_preimage_4bytes = hashed_preimage[:4]
    # extracting the first 28 bits
    hashed_preimage_28bits = bin(int.from_bytes(hashed_preimage_4bytes, "big"))[
        2:
    ].zfill(32)[:28]
    return hashed_preimage_28bits


def find_four_way_collision(watermark: bytes) -> list:
    # create empty dictionary for collisions
    collisions = {}
    while True:
        # create preimage
        pre_image = generate_preimage(watermark)
        # hash the preimage
        hashed_preimage = hash_preimage(pre_image)
        # check to see if hashed preimage is in collisions
        # if yes, add to existing list
        # if no, add to a new list
        if hashed_preimage in collisions:
            collisions[hashed_preimage].append(pre_image)
            # check if collisions length is = 4
            # if yes, return collisions
            if len(collisions[hashed_preimage]) == 4:
                print(collisions[hashed_preimage])
                print(hashed_preimage)
                return collisions[hashed_preimage]
        else:
            collisions[hashed_preimage] = [pre_image]


def save_coin(coin: list, filename: str = "coin.txt"):
    with open(filename, "w") as file:
        for preimage in coin:
            file.write(preimage.hex() + "\n")


def find_forged_netid(original_netid: str, watermark: bytes) -> str:
    id_dictionary = {}
    count = 0
    for l in ascii_lowercase:
        for i in ascii_lowercase:
            for k in range(0, 10000):
                generated_netid = l + i + str(k)

                netid_watermark = compute_watermark(generated_netid)
                id_dictionary[generated_netid] = netid_watermark

                if count % 1000 == 0:
                    # debugging- chatGPT
                    print(f"Checking {generated_netid}: {netid_watermark.hex()}")

                if netid_watermark == watermark:
                    # debugging-chatGPT
                    print(f"Found matching forged NetID: {generated_netid}")
                    # found valid NetID
                    return generated_netid

                count += 1

                if netid_watermark == watermark:
                    return generated_netid

    return None

    # saved forged netid to file


def save_forged_netid(generated_netid: str, filename: str = "forged-watermark.txt"):
    with open(filename, "w") as file:
        file.write(generated_netid + "\n")


def main():
    watermark = compute_watermark(netid)
    # debugging
    print(f"Original NetID: {netid}")
    print(f"Original Watermark: {watermark.hex()}")

    coin = find_four_way_collision(watermark)
    save_coin(coin)

    forged_netid = find_forged_netid(netid, watermark)
    if forged_netid:
        save_forged_netid(forged_netid)
        print("Forged ID found.")
    else:
        print("No forged NetID found.")


if __name__ == "__main__":
    main()
