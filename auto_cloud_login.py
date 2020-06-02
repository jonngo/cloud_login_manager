import pyotp

from PyQt5.QtWidgets import QMessageBox, QInputDialog

from cloud_login_manager import Ui_cloud_login_manager
from PyQt5 import QtCore, QtGui, QtWidgets
import time
from selenium import webdriver
import json

import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ExtendAutoLogIn(Ui_cloud_login_manager):
    CREDENTIAL_FILENAME = "cloud_credentials.json"

    def extendUI(self,cloud_login_manager):
        #Put button objects in a list so it will be easy to iterate
        self.button_list = [self.cloud_a_button, self.cloud_b_button, self.cloud_c_button, self.cloud_d_button, self.cloud_e_button, self.cloud_f_button, self.cloud_g_button, self.cloud_h_button, self.cloud_i_button, self.cloud_j_button]
        self.credentials = {}
        self.configuration_menu_item.triggered.connect(self.configuration)
        self.passphrase_line_edit.textChanged['QString'].connect(self.show_option_on_passphrase_change)

        for i in range(0,10):
            self.button_list[i].clicked.connect(lambda state, x = chr(i+65): self.cloud_button_router(x))

        self.cloud_name_line_edit.textChanged['QString'].connect(lambda state, x = "cloud_name": self.update_cloud_info(x))
        self.email_line_edit.textChanged['QString'].connect(lambda state, x = "email": self.update_cloud_info(x))
        self.password_line_edit.textChanged['QString'].connect(lambda state, x = "password": self.update_cloud_info(x))
        self.cloud_host_line_edit.textChanged['QString'].connect(lambda state, x = "cloud_host": self.update_cloud_info(x))
        self.secret_key_line_edit.textChanged['QString'].connect(lambda state, x = "secret_key": self.update_cloud_info(x))

        self.save_push_button.clicked.connect(self.save_configuration)
        self.clear_push_button.clicked.connect(self.clear_credential_fields)
        self.close_push_button.clicked.connect(self.close_configuration)
        self.refresh_push_button.clicked.connect(self.refresh_configuration)
        self.mfa_pushbutton.clicked.connect(self.mfa_to_browser)

        #Hints
        self.close_push_button.setToolTip("Closes the configuration panel,\nand use existing configuration.")
        self.save_push_button.setToolTip("Save the configuration,\nand use the passphrase to encrypt\nthe password and key fields.")
        self.refresh_push_button.setToolTip("Clear existing configuration\nand load from configuration file.")
        self.clear_push_button.setToolTip("Clear the existing fields")
        self.cloud_a_button.setToolTip("Slot A")
        self.cloud_b_button.setToolTip("Slot B")
        self.cloud_c_button.setToolTip("Slot C")
        self.cloud_d_button.setToolTip("Slot D")
        self.cloud_e_button.setToolTip("Slot E")
        self.cloud_f_button.setToolTip("Slot F")
        self.cloud_g_button.setToolTip("Slot G")
        self.cloud_h_button.setToolTip("Slot H")
        self.cloud_i_button.setToolTip("Slot I")
        self.cloud_j_button.setToolTip("Slot J")
        self.cloud_name_line_edit.setToolTip("Enter cloud name. (e.g. R2 Internal Middleware)")
        self.email_line_edit.setToolTip("Email used to login to the cloud.")
        self.password_line_edit.setToolTip("Password used to login to the cloud.\n(This will be encrypted)")
        self.cloud_host_line_edit.setToolTip("The cloud URL (e.g. https://r2-internal.invencocloud.com")
        self.secret_key_line_edit.setToolTip("Copy the key from WinAuth or other authenticator app you are using.\n(This will be encrypted)")
        self.passphrase_line_edit.setToolTip("Passphrase used to encrypt/decrypt sensitive information and must be at least 4 characters.")
        self.mfa_pushbutton.setToolTip("Paste the MFA code to the browser.\nUsing the last key.")

        reply, pp = self.get_startup_passphrase()

        if reply:
            self.passphrase_line_edit.setText(pp)
            if self.read_configuration():
                #Configuration already exist, so proceed to normal operation.
                cloud_login_manager.show()
                self.show_credential_UI(False)
                self.show_cloud_buttons(False)
                self.show_active_cloud_buttons()
                self.mfa_pushbutton.show()
                cloud_login_manager.adjustSize()
                self.autologin.adjustSize()
                self.statusbar.showMessage("Configuration read successfully.", 2000)

            else:
                #Assume new configuration setup is required
                cloud_login_manager.show()
                self.configuration_menu_item.setEnabled(False)
                self.show_credential_UI(True)
                self.show_cloud_buttons(True)
                self.mfa_pushbutton.hide()
                self.credentials = {}
                self.statusbar.showMessage("Unable to read configuration or the passphrase is incorrect to decrypt stored password.", 3000)

        else:
            cloud_login_manager.close()
            sys.exit()

    def refresh_configuration(self):
        reply = self.dialogYN('Are you sure you want to overwrite from file?', 'Reload')
        if reply:
            if self.read_configuration():
                self.clear_field()
                self.dialog('Config file load successful!','Read File')
            else:
                self.dialog('Cannot read configuration file','Read Error')
                self.credentials = {}
                self.clear_field()


    def close_configuration(self):
        self.remove_empty_cloud_slot()
        missing_fields = self.get_missing_fields()
        if missing_fields:
            cloud_incomplete_info = ""
            for c in missing_fields:
                cloud_incomplete_info += "Cloud "+c+'\n'
            message = "Incomplete:\n"+cloud_incomplete_info.rstrip()
            title = "Cannot Close"
            self.dialog(message,title)
            return
        else:
            if self.credentials:
                self.show_credential_UI(False)
                self.show_cloud_buttons(False)
                self.show_active_cloud_buttons()
                self.mfa_pushbutton.show()
                self.cloud_buttons_frame.adjustSize()
                self.autologin.adjustSize()
                cloud_login_manager.adjustSize()
                self.configuration_menu_item.setEnabled(True)
            else:
                reply = self.dialogYN('No valid credentials.\nClose the app?','Exit')
                if reply:
                    cloud_login_manager.close()
                    sys.exit()

    def clear_credential_fields(self):
        reply = self.dialogYN("Clear all fields","Clear")
        if reply:
            #Remove from dictionary
            if self.cloud_button_line_edit.text():
                index = self.cloud_button_line_edit.text()[-1:]
                if self.credentials:
                    del self.credentials[index]

            self.cloud_button_line_edit.setText('')
            self.cloud_name_line_edit.setText('')
            self.email_line_edit.setText('')
            self.password_line_edit.setText('')
            self.cloud_host_line_edit.setText('')
            self.secret_key_line_edit.setText('')

    def remove_empty_cloud_slot(self):
        r = []
        for i in self.credentials:
            if self.credentials[i]['name'] == '' and self.credentials[i]['username'] == '' and self.credentials[i]['passwd'] == '' and self.credentials[i]['cloud_host'] == '' and self.credentials[i]['secret_key'] == '':
                 r.append(i)

        for i in r:
            del self.credentials[i]

    def get_missing_fields(self):
        r = []
        for i in self.credentials:
            if self.credentials[i]['name'] == '' or self.credentials[i]['username'] == '' or self.credentials[i]['passwd'] == '' or self.credentials[i]['cloud_host'] == '' or self.credentials[i]['secret_key'] == '':
                r.append(i)

        return r


    def save_configuration(self):
        self.remove_empty_cloud_slot()
        missing_fields = self.get_missing_fields()
        if missing_fields:
            cloud_incomplete_info = ""
            for c in missing_fields:
                cloud_incomplete_info += "Cloud "+c+'\n'
            message = "Incomplete:\n"+cloud_incomplete_info.rstrip()
            title = "Cannot Save"
            self.dialog(message,title)
        else:
            #No missing information
            if self.credentials:
                encrypted_credential = self.encrypt_credentials()

                try:
                    with open(self.CREDENTIAL_FILENAME, 'w') as config_file:
                        json.dump(encrypted_credential, config_file)
                        self.dialog('Save successful!','Saving')
                except:
                    self.dialog('Error saving configuration','Saving')
            else:
                self.dialog("Nothing to save!","Saving")

    def encrypt_credentials(self):
        ec = {}
        for i in self.credentials:
            pw = self.encrypt(self.credentials[i]['passwd'])
            sk = self.encrypt(self.credentials[i]['secret_key'])

            ec[i] = {}
            ec[i]['name'] = self.credentials[i]['name']
            ec[i]['username'] = self.credentials[i]['username']
            ec[i]['passwd'] = pw.decode("utf-8")
            ec[i]['cloud_host'] = self.credentials[i]['cloud_host']
            ec[i]['secret_key'] = sk.decode("utf-8")

        return ec

    def get_startup_passphrase(self):
        pp_box = QInputDialog()
        pp_box.setWindowTitle('Passphrase')
        pp_box.setTextEchoMode(QtWidgets.QLineEdit.Password)
        pp_box.setOkButtonText('OK')
        pp_box.setCancelButtonText('Cancel')
        pp_box.setLabelText('Enter your passphrase:')
        pp_box.setToolTip('Passphrase must be at least 4 characters length')
        pp_box.setWhatsThis("Passphrase is used to decrypt stored passwords and encrypt passwords when saving.\nPlease DO NOT forget it.")
        reply = pp_box.exec_()

        pp = pp_box.textValue()

        if reply and len(pp) > 3:
            self.password_line_edit.setText(pp)
            return True, pp
        else:
            return False, pp


    def dialog(self, message, title):
        infoBox = QMessageBox()
        infoBox.setIcon(QMessageBox.Information)
        infoBox.setText(message)
        infoBox.setWindowTitle(title)
        infoBox.setStandardButtons(QMessageBox.Ok)
        infoBox.exec_()

    def dialogYN(self,message,title):
        infoBox = QMessageBox()
        infoBox.setIcon(QMessageBox.Information)
        infoBox.setText(message)
        infoBox.setWindowTitle(title)
        infoBox.setStandardButtons(QMessageBox.Yes|QMessageBox.No)
        reply = infoBox.exec_()

        if reply == QMessageBox.Yes:
            return True
        else:
            return False

    def update_cloud_info(self,field):
        if self.cloud_button_line_edit.text():
            index = self.cloud_button_line_edit.text()[-1:]

            if field == 'cloud_name':
                cloudname = self.cloud_name_line_edit.text()
                self.credentials[index]['name'] = cloudname

            elif field == 'email':
                email = self.email_line_edit.text()
                self.credentials[index]['username'] = email

            elif field == 'password':
                password = self.password_line_edit.text()
                self.credentials[index]['passwd'] = password

            elif field == 'cloud_host':
                cloudhost = self.cloud_host_line_edit.text()
                self.credentials[index]['cloud_host'] = cloudhost

            elif field == 'secret_key':
                secretkey = self.secret_key_line_edit.text()
                self.credentials[index]['secret_key'] = secretkey
        else:
            if field == 'cloud_name':
                self.cloud_name_line_edit.setText('')

            elif field == 'email':
                self.email_line_edit.setText('')

            elif field == 'password':
                self.password_line_edit.setText('')

            elif field == 'cloud_host':
                self.cloud_host_line_edit.setText('')

            elif field == 'secret_key':
                self.secret_key_line_edit.setText('')

    def reset_cloud_button_label(self):
        #Reset cloud button to Cloud A, Cloud B .... Cloud J
        for i in range(0, 10):
            # +65 to get the ASCII of A to J
            self.button_list[i].setText("Cloud " + chr(i + 65))

    def configuration(self):
        self.configuration_menu_item.setEnabled(False)
        self.show_cloud_buttons(True)
        self.show_credential_UI(True)
        self.mfa_pushbutton.hide()

    def show_option_on_passphrase_change(self):
        self.pp = self.passphrase_line_edit.text()
        if len(self.pp) > 3:
            #Switch to edit configuration mode
            self.show_credential_UI(True)
            self.show_cloud_buttons(True)
        else:
            #Not a valid passphrase length, show only passphrase field
            self.configuration_menu_item.setEnabled(False)
            self.show_credential_UI(False)
            self.show_cloud_buttons(False)
            self.passphrase_line_edit.show()

    def read_configuration(self):
        try:
            with open(self.CREDENTIAL_FILENAME, 'r') as f:
                self.credentials = json.load(f)

                for i in self.credentials:
                    decrypted_password = self.decrypt(self.credentials[i]['passwd'])
                    decrypted_secret_key = self.decrypt(self.credentials[i]['secret_key'])
                    self.credentials[i]['passwd'] = decrypted_password
                    self.credentials[i]['secret_key'] = decrypted_secret_key

                return True
        except (Exception):
            return False

    def generate_key(self):
        salt = b'\x97[\x07-\x16\xc7@>\xe4\xcfI\x99\xder\x92\x19'

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        password = self.passphrase_line_edit.text().encode()

        key = base64.urlsafe_b64encode(kdf.derive(password))

        return key


    def encrypt(self, secret):
        return Fernet(self.generate_key()).encrypt(secret.encode())

    def decrypt(self, secret):
        return Fernet(self.generate_key()).decrypt(secret.encode()).decode()

    def clear_field(self):
        self.cloud_button_line_edit.setText("")
        self.cloud_name_line_edit.setText("")
        self.email_line_edit.setText("")
        self.cloud_host_line_edit.setText("")
        self.password_line_edit.setText("")
        self.secret_key_line_edit.setText("")

    def show_credential_UI(self,show_flag):
        if show_flag:
            self.cloud_button_label.show()
            self.cloud_label.show()
            self.cloud_name_label.show()
            self.email_label.show()
            self.password_label.show()
            self.cloud_host_label.show()
            self.secret_key_label.show()
            self.cloud_name_line_edit.show()
            self.email_line_edit.show()
            self.password_line_edit.show()
            self.cloud_host_line_edit.show()
            self.secret_key_line_edit.show()
            self.clear_push_button.show()
            self.save_push_button.show()
            self.refresh_push_button.show()
            self.close_push_button.show()
            self.cloud_button_line_edit.show()
            self.invenco_logo.show()
            self.verticalLayout_2.setEnabled(True)
        else:
            self.cloud_button_label.hide()
            self.cloud_label.hide()
            self.cloud_name_label.hide()
            self.email_label.hide()
            self.password_label.hide()
            self.cloud_host_label.hide()
            self.secret_key_label.hide()
            self.cloud_name_line_edit.hide()
            self.email_line_edit.hide()
            self.password_line_edit.hide()
            self.cloud_host_line_edit.hide()
            self.secret_key_line_edit.hide()
            self.clear_push_button.hide()
            self.save_push_button.hide()
            self.refresh_push_button.hide()
            self.close_push_button.hide()
            self.cloud_button_line_edit.hide()
            self.invenco_logo.hide()
            self.verticalLayout_2.setEnabled(False)

    def show_active_cloud_buttons(self):
        #self.cloud_buttons_frame.setGeometry(QtCore.QRect(0, 0, 157, 100))
        for i in self.credentials:
            if self.credentials[i]['name']:
                if i == 'A':
                    self.cloud_a_button.setText(self.credentials[i]['name'])
                    self.cloud_a_button.show()
                elif i == 'B':
                    self.cloud_b_button.setText(self.credentials[i]['name'])
                    self.cloud_b_button.show()
                elif i == 'C':
                    self.cloud_c_button.setText(self.credentials[i]['name'])
                    self.cloud_c_button.show()
                elif i == 'D':
                    self.cloud_d_button.setText(self.credentials[i]['name'])
                    self.cloud_d_button.show()
                elif i == 'E':
                    self.cloud_e_button.setText(self.credentials[i]['name'])
                    self.cloud_e_button.show()
                elif i == 'F':
                    self.cloud_f_button.setText(self.credentials[i]['name'])
                    self.cloud_f_button.show()
                elif i == 'G':
                    self.cloud_g_button.setText(self.credentials[i]['name'])
                    self.cloud_g_button.show()
                elif i == 'H':
                    self.cloud_h_button.setText(self.credentials[i]['name'])
                    self.cloud_h_button.show()
                elif i == 'I':
                    self.cloud_i_button.setText(self.credentials[i]['name'])
                    self.cloud_i_button.show()
                elif i == 'J':
                    self.cloud_j_button.setText(self.credentials[i]['name'])
                    self.cloud_j_button.show()

    def show_cloud_buttons(self,show_flag):
        if show_flag:
            self.cloud_a_button.setText("Cloud A")
            self.cloud_b_button.setText("Cloud B")
            self.cloud_c_button.setText("Cloud C")
            self.cloud_d_button.setText("Cloud D")
            self.cloud_e_button.setText("Cloud E")
            self.cloud_f_button.setText("Cloud F")
            self.cloud_g_button.setText("Cloud G")
            self.cloud_h_button.setText("Cloud H")
            self.cloud_i_button.setText("Cloud I")
            self.cloud_j_button.setText("Cloud J")
            for button in self.button_list:
                button.show()
            self.passphrase_line_edit.show()
        else:
            for button in self.button_list:
                button.hide()
            self.passphrase_line_edit.hide()

    def cloud_button_router(self, index):
        if self.cloud_label.isVisible():
            self.clear_field()
            self.cloud_button_line_edit.setText("Cloud "+str(index))

            try:
                if self.credentials[index]:
                    self.cloud_name_line_edit.setText(self.credentials[index]['name'])
                    self.email_line_edit.setText(self.credentials[index]['username'])
                    self.password_line_edit.setText(self.credentials[index]['passwd'])
                    self.cloud_host_line_edit.setText(self.credentials[index]['cloud_host'])
                    self.secret_key_line_edit.setText(self.credentials[index]['secret_key'])
            except KeyError:
                self.credentials[index] = {}
                self.credentials[index]['name'] = ''
                self.credentials[index]['username'] = ''
                self.credentials[index]['passwd'] = ''
                self.credentials[index]['cloud_host'] = ''
                self.credentials[index]['secret_key'] = ''
        else:
            self.open_invenco_cloud(index)

    def mfa_to_browser(self):
        try:
            # Get the authentication code
            totp = pyotp.TOTP(self.secret_key)
            email_field = self.driver.find_element_by_id("passConfirmDialog")
            email_field.send_keys(totp.now())
        except:
            self.statusbar.showMessage("Cannot find the MFA dialog box", 1500)

    def open_invenco_cloud(self, index):
        username = self.credentials[index]['username']
        passwd = self.credentials[index]['passwd']
        cloud_host = self.credentials[index]['cloud_host']
        self.secret_key = self.credentials[index]['secret_key']

        #Open Chrome browser
        #Remove the 'Chrome run by automation'
        #chrome_options = webdriver.ChromeOptions()
        #chrome_options.add_argument("--disable-infobars")
        #Argument has explanation below
        #args = ["hide_console",]
        #self.driver = webdriver.Chrome(service_args=args, options=chrome_options)
        #self.driver = webdriver.Chrome('C://Users//jonathann//Downloads//chromedriver_win32')

        self.driver = webdriver.Firefox(executable_path='geckodriver-v0.24.0-win64/geckodriver.exe')
        self.driver.get(cloud_host)
        time.sleep(2)

        #Enter email and password
        email_field = self.driver.find_element_by_id("email")
        email_field.send_keys(username)

        passwd_field = self.driver.find_element_by_id("passwd")
        passwd_field.send_keys(passwd)

        login_button = self.driver.find_element_by_xpath("/html/body/div/div[2]/div[1]/main/form/div/button")
        login_button.click()

        #Get the authentication code
        totp = pyotp.TOTP(self.secret_key)

        #Enter auth code to browser
        time.sleep(2)
        mfa_field = self.driver.find_element_by_id("mfa")
        mfa_field.send_keys(totp.now())

        verify_button = self.driver.find_element_by_xpath("/html/body/div/div[2]/div[1]/main/div/div/div/div/div/div[1]/div[2]/form/button")
        verify_button.click()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    cloud_login_manager = QtWidgets.QMainWindow()
    ui = ExtendAutoLogIn()
    ui.setupUi(cloud_login_manager)
    ui.extendUI(cloud_login_manager)
    sys.exit(app.exec_())


'''
Python don't have the HideCommandPromptWindow like in C#, so someone in Stack Overflow contributed a workaround.
This will hide the annoying command prompt when launching the Chrome web browser:
 
STEP 1
Locate service.py, generally in "X:\YourPythonFold\Lib\site-packages\selenium\webdriver\common\service.py"

STEP 2
Replace these lines (n° 72-76 approximately, below start method def):

self.process = subprocess.Popen(cmd, env=self.env,
                                            close_fds=platform.system() != 'Windows',
                                            stdout=self.log_file,
                                            stderr=self.log_file,
                                            stdin=PIPE)
with

if any("hide_console" in arg for arg in self.command_line_args()):
                self.process = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, creationflags=0x08000000)
            else:
                self.process = subprocess.Popen(cmd, env=self.env, close_fds=platform.system() != 'Windows', stdout=self.log_file, stderr=self.log_file, stdin=PIPE)

Finally in your code, when you setup your driver (I chose Chrome as example):

args = ["hide_console", ]
driver = webdriver.Chrome("your-path-to-chromedriver.exe", service_args=args, ...)
'''

