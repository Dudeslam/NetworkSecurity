from ppmcrypt import PPMImage
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
image = PPMImage.load_from_file(open('tux.ppm', 'rb'))
image.encrypt(key, 'ecb')
image.data[42]=0x42
image.write_to_file(open('image_encrypted.ppm', 'wb'))

