# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'cloud_login_manager.ui'
#
# Created by: PyQt5 UI code generator 5.9.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_cloud_login_manager(object):
    def setupUi(self, cloud_login_manager):
        cloud_login_manager.setObjectName("cloud_login_manager")
        cloud_login_manager.resize(645, 483)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(cloud_login_manager.sizePolicy().hasHeightForWidth())
        cloud_login_manager.setSizePolicy(sizePolicy)
        self.autologin = QtWidgets.QWidget(cloud_login_manager)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.autologin.sizePolicy().hasHeightForWidth())
        self.autologin.setSizePolicy(sizePolicy)
        self.autologin.setObjectName("autologin")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.autologin)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.cloud_buttons_frame = QtWidgets.QFrame(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_buttons_frame.sizePolicy().hasHeightForWidth())
        self.cloud_buttons_frame.setSizePolicy(sizePolicy)
        self.cloud_buttons_frame.setFrameShape(QtWidgets.QFrame.Box)
        self.cloud_buttons_frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.cloud_buttons_frame.setObjectName("cloud_buttons_frame")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.cloud_buttons_frame)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.passphrase_line_edit = QtWidgets.QLineEdit(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.passphrase_line_edit.sizePolicy().hasHeightForWidth())
        self.passphrase_line_edit.setSizePolicy(sizePolicy)
        self.passphrase_line_edit.setToolTip("")
        self.passphrase_line_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.passphrase_line_edit.setObjectName("passphrase_line_edit")
        self.verticalLayout.addWidget(self.passphrase_line_edit)
        self.cloud_a_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_a_button.sizePolicy().hasHeightForWidth())
        self.cloud_a_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_a_button.setFont(font)
        self.cloud_a_button.setObjectName("cloud_a_button")
        self.verticalLayout.addWidget(self.cloud_a_button)
        self.cloud_b_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_b_button.sizePolicy().hasHeightForWidth())
        self.cloud_b_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_b_button.setFont(font)
        self.cloud_b_button.setObjectName("cloud_b_button")
        self.verticalLayout.addWidget(self.cloud_b_button)
        self.cloud_c_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_c_button.sizePolicy().hasHeightForWidth())
        self.cloud_c_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_c_button.setFont(font)
        self.cloud_c_button.setObjectName("cloud_c_button")
        self.verticalLayout.addWidget(self.cloud_c_button)
        self.cloud_d_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_d_button.sizePolicy().hasHeightForWidth())
        self.cloud_d_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_d_button.setFont(font)
        self.cloud_d_button.setObjectName("cloud_d_button")
        self.verticalLayout.addWidget(self.cloud_d_button)
        self.cloud_e_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_e_button.sizePolicy().hasHeightForWidth())
        self.cloud_e_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_e_button.setFont(font)
        self.cloud_e_button.setObjectName("cloud_e_button")
        self.verticalLayout.addWidget(self.cloud_e_button)
        self.cloud_f_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_f_button.sizePolicy().hasHeightForWidth())
        self.cloud_f_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_f_button.setFont(font)
        self.cloud_f_button.setObjectName("cloud_f_button")
        self.verticalLayout.addWidget(self.cloud_f_button)
        self.cloud_g_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_g_button.sizePolicy().hasHeightForWidth())
        self.cloud_g_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_g_button.setFont(font)
        self.cloud_g_button.setObjectName("cloud_g_button")
        self.verticalLayout.addWidget(self.cloud_g_button)
        self.cloud_h_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_h_button.sizePolicy().hasHeightForWidth())
        self.cloud_h_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_h_button.setFont(font)
        self.cloud_h_button.setObjectName("cloud_h_button")
        self.verticalLayout.addWidget(self.cloud_h_button)
        self.cloud_i_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_i_button.sizePolicy().hasHeightForWidth())
        self.cloud_i_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_i_button.setFont(font)
        self.cloud_i_button.setObjectName("cloud_i_button")
        self.verticalLayout.addWidget(self.cloud_i_button)
        self.cloud_j_button = QtWidgets.QPushButton(self.cloud_buttons_frame)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_j_button.sizePolicy().hasHeightForWidth())
        self.cloud_j_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_j_button.setFont(font)
        self.cloud_j_button.setObjectName("cloud_j_button")
        self.verticalLayout.addWidget(self.cloud_j_button)
        self.mfa_pushbutton = QtWidgets.QPushButton(self.cloud_buttons_frame)
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setItalic(True)
        self.mfa_pushbutton.setFont(font)
        self.mfa_pushbutton.setObjectName("mfa_pushbutton")
        self.verticalLayout.addWidget(self.mfa_pushbutton)
        self.verticalLayout_3.addLayout(self.verticalLayout)
        self.horizontalLayout.addWidget(self.cloud_buttons_frame)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.cloud_label = QtWidgets.QLabel(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_label.sizePolicy().hasHeightForWidth())
        self.cloud_label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.cloud_label.setFont(font)
        self.cloud_label.setAlignment(QtCore.Qt.AlignCenter)
        self.cloud_label.setWordWrap(False)
        self.cloud_label.setObjectName("cloud_label")
        self.verticalLayout_2.addWidget(self.cloud_label)
        self.formLayout = QtWidgets.QFormLayout()
        self.formLayout.setVerticalSpacing(18)
        self.formLayout.setObjectName("formLayout")
        self.cloud_button_label = QtWidgets.QLabel(self.autologin)
        self.cloud_button_label.setObjectName("cloud_button_label")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.cloud_button_label)
        self.cloud_button_line_edit = QtWidgets.QLineEdit(self.autologin)
        self.cloud_button_line_edit.setEnabled(False)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_button_line_edit.sizePolicy().hasHeightForWidth())
        self.cloud_button_line_edit.setSizePolicy(sizePolicy)
        self.cloud_button_line_edit.setMinimumSize(QtCore.QSize(250, 0))
        self.cloud_button_line_edit.setObjectName("cloud_button_line_edit")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.cloud_button_line_edit)
        self.cloud_name_label = QtWidgets.QLabel(self.autologin)
        self.cloud_name_label.setObjectName("cloud_name_label")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.cloud_name_label)
        self.cloud_name_line_edit = QtWidgets.QLineEdit(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_name_line_edit.sizePolicy().hasHeightForWidth())
        self.cloud_name_line_edit.setSizePolicy(sizePolicy)
        self.cloud_name_line_edit.setMinimumSize(QtCore.QSize(250, 0))
        self.cloud_name_line_edit.setObjectName("cloud_name_line_edit")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.cloud_name_line_edit)
        self.email_label = QtWidgets.QLabel(self.autologin)
        self.email_label.setObjectName("email_label")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.email_label)
        self.email_line_edit = QtWidgets.QLineEdit(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.email_line_edit.sizePolicy().hasHeightForWidth())
        self.email_line_edit.setSizePolicy(sizePolicy)
        self.email_line_edit.setMinimumSize(QtCore.QSize(250, 0))
        self.email_line_edit.setObjectName("email_line_edit")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.email_line_edit)
        self.password_label = QtWidgets.QLabel(self.autologin)
        self.password_label.setObjectName("password_label")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.LabelRole, self.password_label)
        self.password_line_edit = QtWidgets.QLineEdit(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.password_line_edit.sizePolicy().hasHeightForWidth())
        self.password_line_edit.setSizePolicy(sizePolicy)
        self.password_line_edit.setMinimumSize(QtCore.QSize(250, 0))
        self.password_line_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_line_edit.setObjectName("password_line_edit")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.FieldRole, self.password_line_edit)
        self.cloud_host_label = QtWidgets.QLabel(self.autologin)
        self.cloud_host_label.setObjectName("cloud_host_label")
        self.formLayout.setWidget(4, QtWidgets.QFormLayout.LabelRole, self.cloud_host_label)
        self.cloud_host_line_edit = QtWidgets.QLineEdit(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cloud_host_line_edit.sizePolicy().hasHeightForWidth())
        self.cloud_host_line_edit.setSizePolicy(sizePolicy)
        self.cloud_host_line_edit.setMinimumSize(QtCore.QSize(250, 0))
        self.cloud_host_line_edit.setObjectName("cloud_host_line_edit")
        self.formLayout.setWidget(4, QtWidgets.QFormLayout.FieldRole, self.cloud_host_line_edit)
        self.secret_key_label = QtWidgets.QLabel(self.autologin)
        self.secret_key_label.setObjectName("secret_key_label")
        self.formLayout.setWidget(5, QtWidgets.QFormLayout.LabelRole, self.secret_key_label)
        self.secret_key_line_edit = QtWidgets.QLineEdit(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.secret_key_line_edit.sizePolicy().hasHeightForWidth())
        self.secret_key_line_edit.setSizePolicy(sizePolicy)
        self.secret_key_line_edit.setMinimumSize(QtCore.QSize(250, 0))
        self.secret_key_line_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.secret_key_line_edit.setObjectName("secret_key_line_edit")
        self.formLayout.setWidget(5, QtWidgets.QFormLayout.FieldRole, self.secret_key_line_edit)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setSpacing(10)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.clear_push_button = QtWidgets.QPushButton(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.clear_push_button.sizePolicy().hasHeightForWidth())
        self.clear_push_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.clear_push_button.setFont(font)
        self.clear_push_button.setObjectName("clear_push_button")
        self.horizontalLayout_4.addWidget(self.clear_push_button)
        self.save_push_button = QtWidgets.QPushButton(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.save_push_button.sizePolicy().hasHeightForWidth())
        self.save_push_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.save_push_button.setFont(font)
        self.save_push_button.setObjectName("save_push_button")
        self.horizontalLayout_4.addWidget(self.save_push_button)
        self.formLayout.setLayout(6, QtWidgets.QFormLayout.FieldRole, self.horizontalLayout_4)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setSpacing(10)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem1)
        self.refresh_push_button = QtWidgets.QPushButton(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.refresh_push_button.sizePolicy().hasHeightForWidth())
        self.refresh_push_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.refresh_push_button.setFont(font)
        self.refresh_push_button.setObjectName("refresh_push_button")
        self.horizontalLayout_6.addWidget(self.refresh_push_button)
        self.close_push_button = QtWidgets.QPushButton(self.autologin)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.close_push_button.sizePolicy().hasHeightForWidth())
        self.close_push_button.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.close_push_button.setFont(font)
        self.close_push_button.setObjectName("close_push_button")
        self.horizontalLayout_6.addWidget(self.close_push_button)
        self.formLayout.setLayout(7, QtWidgets.QFormLayout.FieldRole, self.horizontalLayout_6)
        self.verticalLayout_2.addLayout(self.formLayout)
        self.invenco_logo = QtWidgets.QLabel(self.autologin)
        self.invenco_logo.setText("")
        self.invenco_logo.setPixmap(QtGui.QPixmap("invenco.png"))
        self.invenco_logo.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.invenco_logo.setObjectName("invenco_logo")
        self.verticalLayout_2.addWidget(self.invenco_logo)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        cloud_login_manager.setCentralWidget(self.autologin)
        self.menubar = QtWidgets.QMenuBar(cloud_login_manager)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 645, 21))
        self.menubar.setObjectName("menubar")
        self.menu_File = QtWidgets.QMenu(self.menubar)
        self.menu_File.setObjectName("menu_File")
        cloud_login_manager.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(cloud_login_manager)
        self.statusbar.setObjectName("statusbar")
        cloud_login_manager.setStatusBar(self.statusbar)
        self.configuration_menu_item = QtWidgets.QAction(cloud_login_manager)
        self.configuration_menu_item.setObjectName("configuration_menu_item")
        self.exit_menu_item = QtWidgets.QAction(cloud_login_manager)
        self.exit_menu_item.setObjectName("exit_menu_item")
        self.menu_File.addAction(self.configuration_menu_item)
        self.menu_File.addAction(self.exit_menu_item)
        self.menubar.addAction(self.menu_File.menuAction())

        self.retranslateUi(cloud_login_manager)
        self.exit_menu_item.triggered.connect(cloud_login_manager.close)
        QtCore.QMetaObject.connectSlotsByName(cloud_login_manager)

    def retranslateUi(self, cloud_login_manager):
        _translate = QtCore.QCoreApplication.translate
        cloud_login_manager.setWindowTitle(_translate("cloud_login_manager", "CLM"))
        self.cloud_a_button.setText(_translate("cloud_login_manager", "Cloud A"))
        self.cloud_b_button.setText(_translate("cloud_login_manager", "Cloud B"))
        self.cloud_c_button.setText(_translate("cloud_login_manager", "Cloud C"))
        self.cloud_d_button.setText(_translate("cloud_login_manager", "Cloud D"))
        self.cloud_e_button.setText(_translate("cloud_login_manager", "Cloud E"))
        self.cloud_f_button.setText(_translate("cloud_login_manager", "Cloud F"))
        self.cloud_g_button.setText(_translate("cloud_login_manager", "Cloud G"))
        self.cloud_h_button.setText(_translate("cloud_login_manager", "Cloud H"))
        self.cloud_i_button.setText(_translate("cloud_login_manager", "Cloud I"))
        self.cloud_j_button.setText(_translate("cloud_login_manager", "Cloud J"))
        self.mfa_pushbutton.setText(_translate("cloud_login_manager", "MFA"))
        self.cloud_label.setText(_translate("cloud_login_manager", "Cloud Login Info"))
        self.cloud_button_label.setText(_translate("cloud_login_manager", "Cloud Button"))
        self.cloud_name_label.setText(_translate("cloud_login_manager", "Cloud Name"))
        self.email_label.setText(_translate("cloud_login_manager", "Email"))
        self.password_label.setText(_translate("cloud_login_manager", "Password"))
        self.cloud_host_label.setText(_translate("cloud_login_manager", "Cloud Host"))
        self.secret_key_label.setText(_translate("cloud_login_manager", "Secret Key"))
        self.clear_push_button.setText(_translate("cloud_login_manager", "Clea&r"))
        self.save_push_button.setText(_translate("cloud_login_manager", "&Save"))
        self.refresh_push_button.setText(_translate("cloud_login_manager", "&Refresh"))
        self.close_push_button.setText(_translate("cloud_login_manager", "&Close"))
        self.menu_File.setTitle(_translate("cloud_login_manager", "&File"))
        self.configuration_menu_item.setText(_translate("cloud_login_manager", "&Configuration"))
        self.exit_menu_item.setText(_translate("cloud_login_manager", "E&xit"))

