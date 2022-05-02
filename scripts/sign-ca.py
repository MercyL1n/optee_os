
def get_args():
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('--key', required=True, help='Name of key file')
	parser.add_argument('--passcode', required=False, help='Name of key passcode file')
	parser.add_argument('--in', required=True, dest='inf', \
			help='Name of in file')
	parser.add_argument('--out', required=True, help='Name of out file')
	return parser.parse_args()

def main():
	from Crypto.Signature import PKCS1_v1_5
	from Crypto.Hash import SHA256
	from Crypto.PublicKey import RSA
	import struct

	args = get_args()

	if args.passcode:
		passcode=open(args.passcode).readline().rstrip()

	f = open(args.key, 'rb')
	if args.passcode:
		key = RSA.importKey(f.read(), passcode)
	else:
		key = RSA.importKey(f.read())
	f.close()


	f = open(args.inf, 'rb')
	img = f.read()
	f.close()

	signer = PKCS1_v1_5.new(key)
	h = SHA256.new()

	digest_len = h.digest_size
	sig_len = len(signer.sign(h))
	img_size = len(img)
	print "img_size is:", img_size

	magic = 0x4f545348	# SHDR_MAGIC
	sig_algo = 0x70004830	# TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
        hash_algo = 0x50000004  # TEE_ALG_SHA256
	shdr = struct.pack('<IIIIHH', \
						magic, img_size, hash_algo, sig_algo, digest_len, sig_len)

	h.update(shdr)
	h.update(img)

	sig = signer.sign(h)

	f = open(args.out, 'wb')
	f.write(shdr)
	f.write(sig)
	f.close()

if __name__ == "__main__":
	main()