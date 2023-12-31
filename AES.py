from tkinter import *
import tkinter.ttk as ttk
from tkinter import filedialog
import tkinter.messagebox as msgbox

from hashlib import md5
from Cryptodome.Cipher import AES
from os import urandom
import pathlib

import keyboard

# AES를 이용 암호화하려면, 암호화의 대상인 value가 16, 32, 64, 128, 256 바이트의 블록들이어야 한다.
# 위와 같이 암호화 대상인 value를 16, 32, 64, 128, 256 바이트의 블록들로 만드는 것을 padding이라고 한다.
# 내장된 pad 모듈을 이용하여 암호화를 하려는 value를 블록들로 변경한다.

root = Tk()
root.title("AES Encryptor/Decryptor")
root.geometry("450x370")

root.resizable(False, False)


def New_file():
    files = filedialog.askopenfilenames(title="파일 선택", \
        filetypes=(("모든 파일", "*.*"), ("TXT 파일", "*.txt")), initialdir="C:/")
  
    for file in files:
        list_file.delete(0, END)
        list_file.insert(END, file)



def Add_file():
    files = filedialog.askopenfilenames(title="파일 선택", \
        filetypes=(("모든 파일", "*.*"), ("TXT 파일", "*.txt")), initialdir="C:/") 
  
    for file in files:
        list_file.insert(END, file)



def del_file():
    for index in reversed(list_file.curselection()):
        list_file.delete(index)



def How_to_use():
    New_toplevel = Toplevel()
    New_toplevel.geometry("450x370")
    New_toplevel.resizable(False, False)
    New_toplevel.title("How to use?")
    New_toplevel.geometry("400x320")

    ko_label_1 = Label(New_toplevel, text="이 프로그램은 파일을 AES 방식으로 암호화해 파일을 보호할 수 있는 프로그램입니다", wraplength=400)
    ko_label_2 = Label(New_toplevel, text="원하는 파일을 file 메뉴에서 선택한 후 암호화/복호화 할 수 있습니다", wraplength=400)
    ko_label_3 = Label(New_toplevel, text="만약 옳지 않은 파일을 선택할 경우 오류가 발생하거나 작업이 제대로 이루어지지 않을 수 있습니다", wraplength=400)
    ko_label_1.pack()
    ko_label_2.pack(pady=10)
    ko_label_3.pack()


    en_label_1 = Label(New_toplevel, text="This program can protect files by encrypting them with AES.", wraplength=400)
    en_label_2 = Label(New_toplevel, text="You can encrypt/decrypt files by selecting them from the file menu.", wraplength=400)
    en_label_3 = Label(New_toplevel, text="If you select an incorrect file, you may generate an error or the work may not be performed properly.", wraplength=380)
    en_label_1.pack(pady=10)
    en_label_2.pack()
    en_label_3.pack(pady=10)




def derive_key_iv(password, salt, key_length, iv_length): # salt와 passward로 키와 초기화 벡터를 반환해주는 함수
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest() # 만약 .digest()를 생략하면 실제 해시 값을 얻을 수 없으며, 그렇다면 해시 객체 자체만 다룰 뿐이다
        d += d_i # d_i는 중간 해시 값을 의미한다 (d에 계속 추가하는 역할)
    return(d[:key_length], d[key_length:key_length+iv_length])



def encrypt_ready():

    password = password_ent.get()

    if password == '':
        msgbox.showwarning("경고", "비밀번호가 설정되지 않았습니다.")
        return

    all_file_path = list_file.get(0,END)
    files_count = list_file.size()

    for i in range(files_count):

        path = pathlib.Path(all_file_path[i])

        with open(all_file_path[i], 'rb') as in_file, open(all_file_path[i] + '_encrypted_file' + path.suffix, 'wb') as out_file:
            encrypt(in_file, out_file, password)

    if finished == True:
        msgbox.showinfo("알림", "암호화 성공")



def encrypt(in_file, out_file, password, key_length=32):

    global finished

    try:
        bs = AES.block_size  # 16 bytes (128 bit)
        salt = urandom(bs)  # return a string of random bytes (임의 값)
        key, iv = derive_key_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv) # 생성된 키와 초기화 벡터로 AES 암호화 객체(cipher)를 생성
        out_file.write(salt) 
        finished = False

        while not finished:
            chunk = in_file.read(1024 * bs) # final block/chunk is padded before encryption (16KB)
            if len(chunk) == 0 or len(chunk) % bs != 0: # 만약 읽은 데이터의 길이가 0이거나 블록 크기로 나누어 떨어지지 않는다면 마지막 블록을 위해 패딩을 추가
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += str.encode(padding_length * chr(padding_length))
                finished = True
            out_file.write(cipher.encrypt(chunk))

    except Exception as err:
        msgbox.showerror("알 수 없는 오류 발생", err)
        print(err)
        return
    


def decrypt_ready():

    password = password_ent.get()

    if password == '':
        msgbox.showwarning("경고", "비밀번호가 설정되지 않았습니다.")
        return


    all_file_path = list_file.get(0,END)
    files_count = list_file.size()

    for i in range(files_count):

        path = pathlib.Path(all_file_path[i])

        with open(all_file_path[i], 'rb') as in_file, open(all_file_path[i] + '_decrypted_file' + path.suffix, 'wb') as out_file:
            decrypt(in_file, out_file, password)

    if finished == True:
        msgbox.showinfo("알림", "복호화 성공")



def decrypt(in_file, out_file, password, key_length=32):

    global finished

    try:
        bs = AES.block_size
        salt = in_file.read(bs)
        key, iv = derive_key_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False

        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs)) # (16KB)
            if len(next_chunk) == 0: # 복호화가 끝났을때
                padding_length = chunk[-1] # 마지막 바이트를 읽어와서 그 값으로 패딩된 바이트 수를 나타내게 됩니다 ex) 3 바이트 부족하면 03으로 패딩
                chunk = chunk[:-padding_length] # 패딩된 바이트 수 만큼 뒤쪽의 데이터를 잘라내어 패딩을 제거한 데이터를 얻음
                finished = True 
            out_file.write(bytes(x for x in chunk))

    except Exception as err:
        msgbox.showerror("알 수 없는 오류 발생", err)
        print(err)
        return











menu = Menu(root)
root.config(menu=menu)

menu_file = Menu(menu, tearoff=0) 
menu_file.add_command(label="New file", command=New_file)
menu_file.add_command(label="Add file", command=Add_file)

menu.add_cascade(label="file", menu=menu_file)



menu_info = Menu(menu, tearoff=0) 
menu_info.add_command(label="How to use?", command=How_to_use)

menu.add_cascade(label="Info", menu=menu_info)





list_frame = Frame(root)
list_frame.pack(fill="both", padx=5, pady=5)

Scrollbar = Scrollbar(list_frame)
Scrollbar.pack(side="right", fill="y")

list_file = Listbox(list_frame, selectmode="extended", height=15, yscrollcommand=Scrollbar.set)
list_file.pack(side="left", fill="both", expand="True")
Scrollbar.config(command=list_file.yview)



password_frame = LabelFrame(root, text="Password")
password_frame.pack(fill="x", padx=5, pady=5, ipady=5)

password_ent = Entry(password_frame)
password_ent.pack(side="left", fill="x", expand="True", padx=5, pady=5)



file_frame = Frame(root)
file_frame.pack(fill="x", padx=5, pady=5)

btn_encrypt = Button(file_frame, padx=5, pady=5, width=12, text="Encrypt", command=encrypt_ready)
btn_encrypt.pack(side="left")

btn_decrypt = Button(file_frame, padx=5, pady=5, width=12, text="Decrypt", command=decrypt_ready)
btn_decrypt.pack(side="right")




keyboard.add_hotkey("del", del_file)


root.mainloop()

