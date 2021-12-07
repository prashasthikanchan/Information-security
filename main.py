from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import onetimepad
import cv2
import numpy as np
import zlib

root = Tk()
root.title("Information security")
root.geometry("500x400")
root.iconbitmap('C:/Users/acer/Downloads/my_lock.ico')
root.configure(bg="#ccf5ff")

ste_enc_text_var = StringVar()
ste_enc_image_var = StringVar()
crypt_enc_text_var = StringVar()
crypt_dec_text_var = StringVar()
ste_dec_image_var = StringVar()
ste_enc_output_var = StringVar()


main_frame = LabelFrame(root, bg="#80e5ff", bd=5)
main_frame.place(relx=0.1, rely=0.09, relwidth=0.8, relheight=0.12)


def to_bin(data):
    """Convert `data` to binary format as string"""
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, "08b") for i in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")


def encode(image_name, secret_data):
    # read the image
    image = cv2.imread(image_name)
    # maximum bytes to encode
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    if len(secret_data) > n_bytes:
        print("Encoding data...")
        # converting to bytes
        bytes_secret_data = secret_data.encode('utf-8')
        print("bytes_secret_data:", bytes_secret_data)
        # conversion to bytes
        compress_secret_data = zlib.compress(bytes_secret_data)
        print("compressed text", compress_secret_data)
        compressed_secret_data = compress_secret_data.decode('latin1')
        compressed_secret_data += "^^^"
    else:
        print("Encoding data...")
        compressed_secret_data = secret_data
    data_index = 0
    # add stopping criteria
    compressed_secret_data += '====='
    # convert data to binary
    binary_secret_data = to_bin(compressed_secret_data)
    print(binary_secret_data)
    # size of data to hide
    data_len = len(binary_secret_data)
    for row in image:
        for pixel in row:
            # convert RGB values to binary format
            r, g, b = to_bin(pixel)
            # modify the least significant bit only if there is still data to store
            if data_index < data_len:
                # least significant red pixel bit
                pixel[0] = int(r[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index < data_len:
                # least significant green pixel bit
                pixel[1] = int(g[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            if data_index < data_len:
                # least significant blue pixel bit
                pixel[2] = int(b[:-1] + binary_secret_data[data_index], 2)
                data_index += 1
            # if data is encoded, just break out of the loop
            if data_index >= data_len:
                break
    print("returning from encode")
    return image

def decode(image_name):
    # read the image
    image = cv2.imread(image_name)
    binary_data = ""
    for row in image:
        for pixel in row:
            r, g, b = to_bin(pixel)
            binary_data += r[-1]
            binary_data += g[-1]
            binary_data += b[-1]
    # split by 8-bits
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    # convert from bits to characters
    decoded_data = ""
    for byte in all_bytes:
        decoded_data +=chr(int(byte,2))
        if decoded_data[-5:] == "=====":
            break
    if decoded_data[-8:] == "^^^=====":
        in_bytes = bytes(decoded_data[:-8], 'latin1')
        decompressed_decoded_data = zlib.decompress(in_bytes)
        secret_info = decompressed_decoded_data.decode('utf-8')
    else:
        secret_info = decoded_data[:-5]

    return secret_info

def stegano_encrypt():
    ste_enc_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    ste_enc_frame.place(relx=0.1, rely=0.35, relwidth=0.8, relheight=0.55)

    ste_enc_text = Entry(ste_enc_frame, width=30, textvariable=ste_enc_text_var)
    ste_enc_text.grid(row=0, column=3, padx=5, pady=5)

    ste_enc_textlabel = Label(ste_enc_frame, text="Data to encrypt", bg="#80e5ff")
    ste_enc_textlabel.grid(row=0, column=2, padx=5, pady=5)

    ste_enc_image = Entry(ste_enc_frame, width=30, textvariable=ste_enc_image_var)
    ste_enc_image.grid(row=2, column=3, padx=5, pady=5)

    ste_enc_imagelabel = Label(ste_enc_frame, text="Image name with extension", bg="#80e5ff")
    ste_enc_imagelabel.grid(row=2, column=2, padx=5, pady=5)

    ste_enc_output = Entry(ste_enc_frame, width=30, textvariable=ste_enc_output_var)
    ste_enc_output.grid(row=4, column=3, padx=5, pady=5)

    ste_enc_outputlabel = Label(ste_enc_frame, text="Save as", bg="#80e5ff")
    ste_enc_outputlabel.grid(row=4, column=2, padx=5, pady=5)

    def browse_file():
        root.filename = filedialog.askopenfilename(initialdir="/", title="Select a png file", filetype=
                                                   (("png files", "*.png"), ("all files", "*.*")))
        ste_enc_image.insert(0, root.filename)
    ste_enc_browse = Button(ste_enc_frame, text="Browse", command=browse_file)
    ste_enc_browse.grid(row=3, column=3, padx=5, pady=5)

    ste_enc_submit_btn = Button(ste_enc_frame, text="Submit", command=ste_enc_submit)
    ste_enc_submit_btn.grid(row=5, column=3, padx=10, pady=10)


def ste_enc_submit():
    my_textval = ste_enc_text_var.get()
    my_imageval = ste_enc_image_var.get()
    my_outputval = ste_enc_output_var.get()

    print("value:{}".format(my_textval))

    if my_textval == "":
        print("Text not found")
        messagebox.showerror("Error", "image not found")
    elif my_imageval == "":
        print("Image not found")
        messagebox.showerror("Error", "Image not found")
    else:
        print("imageval:{}".format(my_imageval))
        input_image = my_imageval
        secret_data = my_textval
        to_bin(secret_data)
        output_image = my_outputval
        encoded_image = encode(image_name=input_image, secret_data=secret_data)
        print("encoded image: {}".format(encoded_image))
        cv2.imwrite(output_image, encoded_image)
        print("encryption done")
        messagebox.showinfo("Note", "Encoded image downloaded")


def stegano_decrypt():
    ste_dec_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    ste_dec_frame.place(relx=0.1, rely=0.35, relwidth=0.8, relheight=0.55)

    ste_dec_image = Entry(ste_dec_frame, width=30, textvariable=ste_dec_image_var)
    ste_dec_image.grid(row=6, column=3, padx=5, pady=5)

    ste_dec_imagelabel = Label(ste_dec_frame, text="Image name with extension", bg="#80e5ff")
    ste_dec_imagelabel.grid(row=6, column=2, padx=5, pady=5)

    def browse_file():
        root.filename = filedialog.askopenfilename(initialdir="/", title="Select a png file", filetype=
                                                   (("png files", "*.png"), ("all files", "*.*")))
        ste_dec_image.insert(0, root.filename)
    ste_dec_browse = Button(ste_dec_frame, text="Browse", command=browse_file)
    ste_dec_browse.grid(row=7, column=3)

    ste_dec_submit_btn = Button(ste_dec_frame, text="Submit", command=ste_dec_submit)
    ste_dec_submit_btn.grid(row=8, column=3, columnspan=2, padx=10, pady=10)


def ste_dec_submit():
    input_image = ste_dec_image_var.get()

    if input_image == "":
        print("Text not found")
        messagebox.showerror("Error", "Image not found")
    else:
        decoded_data = decode(input_image)
        messagebox.showinfo("decoded data", decoded_data)


def crypt_encrypt():
    crypt_enc_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    crypt_enc_frame.place(relx=0.1, rely=0.35, relwidth=0.8, relheight=0.55)

    crypt_enc_text = Entry(crypt_enc_frame, width=30, textvariable=crypt_enc_text_var)
    crypt_enc_text.grid(row=0, column=3, padx=5, pady=5)

    crypt_enc_textlabel = Label(crypt_enc_frame, text="Data to encrypt", bg="#80e5ff")
    crypt_enc_textlabel.grid(row=0, column=2, padx=5, pady=5)

    crypt_enc_submit_btn = Button(crypt_enc_frame, text="Submit", command=crypt_enc_submit)
    crypt_enc_submit_btn.grid(row=8, column=3, columnspan=2, padx=10, pady=10)


def crypt_enc_submit():
    input_text = crypt_enc_text_var.get()

    crypt_enc_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    crypt_enc_frame.place(relx=0.1, rely=0.35, relwidth=0.8, relheight=0.55)

    crypt_enc_output = Entry(crypt_enc_frame, width=30)
    crypt_enc_output.grid(row=0, column=3, padx=5, pady=5)

    crypt_enc_outputlabel = Label(crypt_enc_frame, text="Encrypted data", bg="#80e5ff")
    crypt_enc_outputlabel.grid(row=0, column=2, padx=5, pady=5)

    if input_text == "":
        print("Text not found")
        messagebox.showerror("Error", "Image not found")
    else:
        cipher_text = onetimepad.encrypt(input_text, 'random')
        crypt_enc_output.insert(0, cipher_text)


def crypt_decrypt():
    crypt_dec_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    crypt_dec_frame.place(relx=0.1, rely=0.35, relwidth=0.8, relheight=0.55)

    crypt_dec_textlabel = Label(crypt_dec_frame, text="Data to Decrypt", bg="#80e5ff")
    crypt_dec_textlabel.grid(row=0, column=2, padx=5, pady=5)

    crypt_dec_text = Entry(crypt_dec_frame, width=30, textvariable=crypt_dec_text_var)
    crypt_dec_text.grid(row=0, column=3, padx=5, pady=5)

    crypt_dec_submit_btn = Button(crypt_dec_frame, text="Submit", command=crypt_dec_submit)
    crypt_dec_submit_btn.grid(row=8, column=3, columnspan=2, padx=10, pady=10)


def crypt_dec_submit():
    output_text = crypt_dec_text_var.get()

    crypt_dec_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    crypt_dec_frame.place(relx=0.1, rely=0.35, relwidth=0.8, relheight=0.55)

    crypt_dec_plaintextlabel = Label(crypt_dec_frame, text="Decrypted data", bg="#80e5ff")
    crypt_dec_plaintextlabel.grid(row=9, column=2, padx=5, pady=5)

    crypt_dec_plaintext = Entry(crypt_dec_frame, width=30)
    crypt_dec_plaintext.grid(row=9, column=3, padx=5, pady=5)

    if output_text == "":
        print("Text not found")
        messagebox.showerror("Error", "Text not found")
    else:
        plain_text = onetimepad.decrypt(output_text, 'random')
        crypt_dec_plaintext.insert(0, plain_text)


def steganography():
    ste_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    ste_frame.place(relx=0.1, rely=0.21, relwidth=0.8, relheight=0.12)

    my_encrypt = Button(ste_frame, text="Encrypt", command=stegano_encrypt)
    my_encrypt.place(relx=0.35, rely=0.15)

    my_decrypt = Button(ste_frame, text="Decrypt", command=stegano_decrypt)
    my_decrypt.place(relx=0.5, rely=0.15)


def cryptography():
    crypt_frame = LabelFrame(root, bg="#80e5ff", bd=5)
    crypt_frame.place(relx=0.1, rely=0.21, relwidth=0.8, relheight=0.12)

    crypt_enc = Button(crypt_frame, text="Encrypt", command=crypt_encrypt)
    crypt_enc.place(relx=0.35, rely=0.1)

    crypt_dec = Button(crypt_frame, text="Decrypt", command=crypt_decrypt)
    crypt_dec.place(relx=0.5, rely=0.1)


steganography_btn = Button(main_frame, text="Steganography", command=steganography)
steganography_btn.place(relx=0.25, rely=0.1)

cryptography_btn = Button(main_frame, text="Cryptography", command=cryptography)
cryptography_btn.place(relx=0.5, rely=0.1)

root.mainloop()
