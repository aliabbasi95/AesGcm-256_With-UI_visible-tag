from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import aes
from cryptography import exceptions


def main():
    win = Tk()
    win.title('Enc & Dec')
    win.resizable(False, False)
    win.geometry("775x436")
    win.configure(bg='white')

    def save_filename():
        global save_filename_address
        save_filename_address = filedialog.asksaveasfilename(initialdir="/", title="Select file",
                                                             filetypes=(("text files", "*.txt"), ("all files", "*.*")))

    def open_filename():
        global open_filename_address
        open_filename_address = filedialog.askopenfilename(initialdir="/", title="Select file",
                                                           filetypes=(("text files", "*.txt"), ("all files", "*.*")))

    def open_encrypt():
        win.withdraw()
        encrypt_win = Toplevel(win)
        encrypt_win.title('Encrypt')
        encrypt_win.geometry("775x436")
        encrypt_win.resizable(False, False)
        encrypt_win.configure(bg='white')

        def do_close_func():
            encrypt_win.destroy()
            win.deiconify()

        def open_decrypt_mn():
            encrypt_win.destroy()
            open_decrypt()

        mn = Menu(encrypt_win)
        encrypt_win.config(menu=mn)
        menu_mn = Menu(mn, tearoff=0)
        help_mn = Menu(mn, tearoff=0)
        mn.add_cascade(label='Menu', menu=menu_mn)
        mn.add_cascade(label='Help', menu=help_mn)
        menu_mn.add_command(label='Home', command=do_close_func)
        menu_mn.add_command(label='Decrypt', command=open_decrypt_mn)
        help_mn.add_command(label='About', command=open_about)

        lb_left = Label(encrypt_win, height=30, width=40, bg='#027dc5')
        lb_left.place(relx=0, rely=0)

        lock = PhotoImage(file="images/lock.gif")
        lb_lcok = Label(encrypt_win, image=lock, height=105, width=105)
        lb_lcok.photo = lock
        lb_lcok.place(relx=0.185, rely=0.4, anchor=CENTER)

        lb_lcok_text = Label(encrypt_win, text='Encrypt', fg='black', bg='#027dc5', font=('calibri', '18',))
        lb_lcok_text.place(relx=0.185, rely=0.58, anchor=CENTER)

        entry_text = Entry(encrypt_win, width=40, bd=2, relief=GROOVE)
        entry_text.place(relx=0.50, rely=0.16)
        lb_text = Label(encrypt_win, text='Text', fg='black', bg='white', font=('calibri', '12',))
        lb_text.place(relx=0.5, rely=0.1)

        entry_password = Entry(encrypt_win, width=30, show='*', bd=2, relief=GROOVE)
        entry_password.place(relx=0.50, rely=0.30)
        lb_password = Label(encrypt_win, text='Password', bg='white', fg='black', font=('calibri', '12'))
        lb_password.place(relx=0.5, rely=0.23)

        entry_aad = Entry(encrypt_win, width=30, show='*', bd=2, relief=GROOVE)
        entry_aad.place(relx=0.5, rely=0.43)
        lb_aad = Label(encrypt_win, text='Associated data', bg='white', fg='black', font=('calibri', '12'))
        lb_aad.place(relx=0.5, rely=0.37)

        lb_save_filename = Button(encrypt_win, text='Browse', command=save_filename, bg='white', fg='black',
                                  relief=RAISED, font=('calibri', '12'))
        lb_save_filename.place(relx=0.83, rely=0.55)

        lb_give_text = Label(encrypt_win, text='Select address and file name:', bg='white', fg='black',
                             font=('calibri', '12'))
        lb_give_text.place(relx=0.5, rely=0.56)

        def enc():
            try:
                nonce, cipher, tag, salt = aes.encrypt(entry_password.get(), entry_text.get(), entry_aad.get())

                x = open(save_filename_address, 'wb')

                x.write(('Aad: ' + entry_aad.get() + '\n').encode())
                x.write(salt + ('\n').encode())
                x.write(nonce + ('\n').encode())
                x.write(cipher + ('\n').encode())
                x.write(tag + ('\n').encode())

                x.write(('The avove data in the foem string:\nsalt: ' + str(salt) + '\nnonce: ' + str(
                    nonce) + '\ncipher_text: ' + str(cipher) + '\ntag: ' + str(tag)).encode())
                x.close()
                messagebox.showinfo("Complete",
                                    'Your text was encrypted \n\nsalt: ' + str(salt) + '\n\nnonce: ' + str(nonce) +
                                    '\n\nciphertext: ' + str(cipher))
                encrypt_win.destroy()
                win.deiconify()
            except exceptions.InvalidTag:
                messagebox.showerror("Error", 'Your data is inavlid')
                entry_text.delete(0, END)
                entry_password.delete(0, END)
                entry_aad.delete(0, END)

        btn_encrypt2 = Button(encrypt_win, text='Encrypt', command=enc, height=1, width=30, bg='#027dc5', pady=5,
                              font=('calibri', '14'))
        btn_encrypt2.place(relx=0.47, rely=0.8)

        encrypt_win.protocol('WM_DELETE_WINDOW', do_close_func)

    def open_decrypt():
        win.withdraw()
        decrypt_win = Toplevel(win)
        decrypt_win.title('Decrypt')
        decrypt_win.geometry("775x436")
        decrypt_win.resizable(False, False)
        decrypt_win.configure(bg='white')

        def do_close_func():
            decrypt_win.destroy()
            win.deiconify()

        def open_encrypt_mm():
            decrypt_win.destroy()
            open_encrypt()

        mn = Menu(decrypt_win)
        decrypt_win.config(menu=mn)
        menu_mn = Menu(mn, tearoff=0)
        help_mn = Menu(mn, tearoff=0)
        mn.add_cascade(label='Menu', menu=menu_mn)
        mn.add_cascade(label='Help', menu=help_mn)
        menu_mn.add_command(label='Home', command=do_close_func)
        menu_mn.add_command(label='Encrypt', command=open_encrypt_mm)
        help_mn.add_command(label='About', command=open_about)

        lb_left = Label(decrypt_win, height=30, width=40, bg='#027dc5')
        lb_left.place(relx=0, rely=0)

        unlock = PhotoImage(file="images/unlock.gif")
        lb_unlock = Label(decrypt_win, image=unlock, height=105, width=105)
        lb_unlock.photo = unlock
        lb_unlock.place(relx=0.185, rely=0.4, anchor=CENTER)

        lb_ulcok_text = Label(decrypt_win, text='Decrypt', fg='black', bg='#027dc5', font=('calibri', '18'))
        lb_ulcok_text.place(relx=0.18, rely=0.58, anchor=CENTER)

        entry_password = Entry(decrypt_win, width=30, show='*', bd=2, relief=GROOVE)
        entry_password.place(relx=0.5, rely=0.30)
        lb_password = Label(decrypt_win, text='Password:', bg='white', fg='black', font=('calibri', '12'))
        lb_password.place(relx=0.5, rely=0.23)

        lb_save_filename = Button(decrypt_win, text='Browse', command=save_filename, bg='white', fg='black',
                                  relief=RAISED,
                                  font=('calibri', '12'), width=8)
        lb_save_filename.place(relx=0.83, rely=0.55)

        lb_give_text = Label(decrypt_win, text='Select address and file name:', bg='white', fg='black',
                             font=('calibri', '12'))
        lb_give_text.place(relx=0.5, rely=0.56)

        lb_open_filename = Button(decrypt_win, text='open', command=open_filename, bg='white', fg='black',
                                  relief=RAISED,
                                  font=('calibri', '12'), width=8)
        lb_open_filename.place(relx=0.83, rely=0.1)

        lb_open_filename_text = Label(decrypt_win, text='Open CipherText file:', bg='white', fg='black',
                                      font=('calibri', '12'))
        lb_open_filename_text.place(relx=0.5, rely=0.12)

        def dec():
            try:
                f = open(open_filename_address, "rb")

                aad = f.readline()

                aad = aad[5:len(aad) - 1]
                salt = f.readline()

                nonce = f.readline()

                cipher_text = f.readline()

                tag = f.readline()

                salt = salt.replace(b'\n', b'')
                nonce = nonce.replace(b'\n', b'')
                cipher_text = cipher_text.replace(b'\n', b'')
                tag = tag.replace(b'\n', b'')

                ciphertext = aes.decrypt(salt, entry_password.get(), aad, nonce, cipher_text, tag)

                print(ciphertext)
                text_to_save = str(ciphertext)
                x = open(save_filename_address, 'w')
                x.write(text_to_save)
                x.write('\nAad: ' + aad.decode())
                x.close()
                messagebox.showinfo("Complete",
                                    'Your text was decryped\n\nplinetext: ' + ciphertext)

                decrypt_win.destroy()
                win.deiconify()
            except:
                messagebox.showerror("Error", 'Your data is inavlid\ncheck file & password')
                entry_password.delete(0, END)

        btn_decrypt2 = Button(decrypt_win, text='Decrypt', command=dec, height=1, width=30, bg='#027dc5', pady=5,
                              font=('calibri', '14'))
        btn_decrypt2.place(relx=0.47, rely=0.8)

        decrypt_win.protocol('WM_DELETE_WINDOW', do_close_func)

    def open_about():
        about_win = Toplevel(win)
        about_win.title('About')
        about_win.geometry("400x400")
        about_win.resizable(False, False)
        about_win.configure(bg='#027dc5')

        def do_close_func():
            about_win.destroy()
            win.deiconify()

        mn = Menu(about_win)
        about_win.config(menu=mn)
        menu_mn = Menu(mn, tearoff=0)
        mn.add_cascade(label='Menu', menu=menu_mn)
        menu_mn.add_command(label='Home', command=do_close_func)
        menu_mn.add_command(label='Encrypt', command=open_encrypt)
        menu_mn.add_command(label='Decrypt', command=open_decrypt)

        text = Text(about_win, bg='#027dc5', bd=0)
        text.tag_configure('bold_italics', font=('Arial', 12, 'bold', 'italic'))
        text.tag_configure('big', font=('Verdana', 20, 'bold'))
        text.tag_configure('color', font=('Arial', 16))
        text.pack()
        text.insert(END, '\n  Ali Abbasi\n', 'big')
        tt = """
        \n Mail: aliabbasi.95@yahoo.com
        \n Github: github.com/aliabbasi95
        """
        text.insert(END, tt, 'color')

    def win_attr():
        mn = Menu(win)
        win.config(menu=mn)
        menu_mn = Menu(mn, tearoff=0)
        help_mn = Menu(mn, tearoff=0)
        mn.add_cascade(label='Menu', menu=menu_mn)
        mn.add_cascade(label='Help', menu=help_mn)
        menu_mn.add_command(label='Encrypt', command=open_encrypt)
        menu_mn.add_command(label='Decrypt', command=open_decrypt)
        menu_mn.add_command(label='Exit', command=win.destroy)
        help_mn.add_command(label='About', command=open_about)

        bg_image = PhotoImage(file="images/bg_pic.gif")
        bg_label = Label(win, image=bg_image, height=436, width=775)
        bg_label.photo = bg_image
        bg_label.place(relx=0, rely=0, anchor="nw")

        btn_encrypt = Button(win, text='Encrypt', command=open_encrypt, height=1, width=10, bg='#66aacc',
                             font=('Helvetica', '14'), pady=0, padx=0, borderwidth=7, activebackground='#002b66',
                             activeforeground='white')
        btn_encrypt.place(relx=0.02, rely=0.82)

        btn_decrypt = Button(win, text='Decrypt', command=open_decrypt, height=1, width=10, bg='#66aacc',
                             font=('Helvetica', '14'), pady=0, padx=0, borderwidth=7, activebackground='#002b66',
                             activeforeground='white')
        btn_decrypt.place(relx=0.2, rely=0.82)

    win_attr()
    mainloop()


main()
