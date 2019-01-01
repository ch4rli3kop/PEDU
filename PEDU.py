# -*- coding: utf-8 -*- 
import sys
import os
from PyQt4.QtGui import *
from PyQt4.QtCore import*
from PyQt4.QtWebKit import *
import pefile
import codecs

Pfile = 0
filename = ""
filesize = 0


class MyWindow(QMainWindow):
   def __init__(self):
      QMainWindow.__init__(self)

      ### 윈도우 특성 설정 ###
      self.setWindowTitle('PEDU')
      self.setGeometry(400,200,1500,600)
      #self.setWindowIcon(QIcon(''))
      self.statusBar().showMessage('ready')
      self.creat_menubar_child()
      self.creat_menubar()
      self.show()
      self.open_file()
      subWin = subWindow()
      self.setCentralWidget(subWin)
      print (os.getcwd()) #현재 디렉토리의
      print (os.path.realpath(__file__))#파일
      print (os.path.dirname(os.path.realpath(__file__)) )#파일이 위치한 디렉토리
      self.show()
      

   def creat_menubar_child(self):
      ### 메뉴바 설정 ###
      #load file
      self.fileAction1 = QAction("load file",self)
      self.fileAction1.setShortcut("Ctrl+O")
      self.fileAction1.setStatusTip("Load the file in local place")# 밑에서 상태를 알려줌
      self.fileAction1.triggered.connect(self.open_file)

      #exit 
      self.fileAction2 = QAction("Exit",self)
      self.fileAction2.setShortcut("Ctrl+C")
      self.fileAction2.setStatusTip("Exit the App")
      self.fileAction2.triggered.connect(self.close_window)

      #change font
      self.fileAction3 = QAction("Change Font",self)
      self.fileAction3.setShortcut("Ctrl+T")
      self.fileAction3.setStatusTip("Change the string font in application")
      self.fileAction3.triggered.connect(self.change_font)

      #calculater
      self.fileAction4 = QAction("Calculater", self)
      self.fileAction4.setShortcut("Ctrl+E")
      self.fileAction4.setStatusTip("Pop up the calculater")
      self.fileAction4.triggered.connect(self.popCalc)

   def creat_menubar(self):
      ### MenuBar ###
      mainMenu = self.menuBar()
      
      #File      
      fileMenu1 = mainMenu.addMenu('File')
      fileMenu1.addAction(self.fileAction1)
      fileMenu1.addAction(self.fileAction2)

      #Option
      fileMenu2 = mainMenu.addMenu('Options')
      fileMenu2.addAction(self.fileAction3)

      #Tool
      fileMenu3 = mainMenu.addMenu('Tools')
      fileMenu3.addAction(self.fileAction4)

      ### toolbar 설정 ###
      #open_file
      # openIcon = QIcon()
      # openIcon.addFile('openFileImage2.png', QSize(16,16))
      # openAction = QAction(toolIcon, 'open_file', self)
      openAction = QAction(QIcon('file_open.png'), 'Open', self)
      openAction.triggered.connect(self.open_file)

      #exit_file
      exitAction = QAction(QIcon('exit.png'), 'Exit', self)
      exitAction.triggered.connect(self.close_window)

      #change_font
      setFontAction = QAction(QIcon('option.png'), 'Setting', self)
      setFontAction.triggered.connect(self.change_font)

      #pop_calculater
      calcAction = QAction(QIcon('calculater.png'), 'Calculater', self)
      calcAction.triggered.connect(self.popCalc)


      #open_file2
      self.openToolBar = self.addToolBar("Open")
      self.openToolBar.addAction(openAction)

      #exit_file2
      self.exitToolBar = self.addToolBar("Exit")
      self.exitToolBar.addAction(exitAction) 

      #change_font2
      self.setToolBar = self.addToolBar("Setting")
      self.setToolBar.addAction(setFontAction)

      #pop_calculater2
      self.calcToolBar = self.addToolBar("Calculater")
      self.calcToolBar.addAction(calcAction)




   def open_file(self):
      global filename
      filename = QFileDialog.getOpenFileName(self, "Select file")
      global Pfile
      Pfile = pefile.PE(filename)


   def close_window(self):
      result = QMessageBox.question(self, 'Message',"Are you sure you leave?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

      if result == QMessageBox.Yes:
         sys.exit()
      else:
         pass
      

   def change_font(self):
      font, valid = QFontDialog.getFont()
      if valid:
         self.styleChoice.setFont(font)

   def popCalc(self):
      form = calculater()
      form.show()

class calculater(QDialog):
    # 창 초기화
    def __init__(self, parent=None):
        super().__init__(parent)
        self.old = ''
        self.new = '0'
        self.operator = ''

        layout = QGridLayout()
        self.label = QLabel()
        self.label.setText('<p align="right"><font size=30><b>' + self.new + '</b></font></p>')
        layout.addWidget(self.label, 0, 0, 1, 4)  # 0, 0 위치에서 행으로 1칸, 열로 4칸의 크기를 갖도록 함.
        # 버튼 생성과 위치 지정
        for index, value in enumerate(['7', '8', '9', '/', '4', '5', '6', '*', '1', '2', '3', '-', '0', '.', '=', '+']):
            button = QPushButton(value)
            layout.addWidget(button, index // 4 + 1, index % 4)

        self.setLayout(layout)
        self.setWindowTitle('계산기')

        for index, value in enumerate(['7', '8', '9', '/', '4', '5', '6', '*', '1', '2', '3', '-', '0', '.', '=', '+']):
            button = QPushButton(value)
            layout.addWidget(button, index // 4 + 1, index % 4)
            if value in ['/', '*', '-', '+', '=']:
                self.connect(button, SIGNAL('clicked()'), lambda who=value: self.calculate(who))
            else:
                self.connect(button, SIGNAL('clicked()'), lambda who=value: self.num_input(who))

    # 레이블 업데이트
    def updateResult(self, text):
        self.label.setText('<p align="right"><font size=30><b>' + text + '</b></font></p>')  # 항상 현재 값을 표시.

    # 계산 메소드
    def calculate(self, who):
        try:
            # = 버튼 처리
            if who == '=':
                # 이전 값과 연산자가 있을 때만 계산
                if self.old != '' and self.operator != '':
                    self.new = str(eval(self.old + self.operator + self.new))
                    self.old = ''
                    self.operator = who
            # 연산자 처리
            else:
                # 이전 값이 있을 경우 이전 값과 현재 값을 계산 후 연산자 대입.
                if self.old != '':
                    self.new = str(eval(self.old + self.operator + self.new))
                    self.old = ''
                self.operator = who
        except:
            self.new = '오류!'
            self.old = ''
            self.operator = ''
        self.updateResult(self.new)

    # 숫자와 소수점 처리
    def num_input(self, who):
        # 오류가 발생한 경우 초기화
        if self.new == '오류!':
            self.new = '0'
            self.old = ''
            self.operator = ''
        # 계산 후 숫자를 누르면 초기화
        if self.operator == '=':
            self.new = '0'
            self.operator = ''
        # 이전 값은 없고, 연산자가 있을 경우 이전 값에 현재 값을 대입하고, 현재 값 새로 입력.
        if self.old == '' and self.operator != '':
            self.old = self.new
            if who == '.':
                self.new = '0.'
            else:
                self.new = who
        # 일반적인 경우
        else:
            # 소수점일 경우 현재 값에 소수점이 없을 때만 소수점 입력.
            if who == '.':
                if '.' not in self.new:
                    self.new = self.new + who
            else:
                # 현재 값이 0일 경우 숫자를 누르면 그 숫자가 바로 입력.
                if self.new == '0':
                    self.new = who
                else:
                    self.new = self.new + who
        self.updateResult(self.new)


class subWindow(QWidget):

   def __init__(self):
      QWidget.__init__(self)
      self.peInformationToList()
      self.creat_split_window()
      self.offsetStart = 0
      self.size = 0
      self.show()



   def peInformationToList(self):
      self.dos_header=[]

      self.dos_header.append((Pfile.DOS_HEADER.e_magic))
      self.dos_header.append((Pfile.DOS_HEADER.e_cblp))
      self.dos_header.append((Pfile.DOS_HEADER.e_cp))
      self.dos_header.append((Pfile.DOS_HEADER.e_crlc))
      self.dos_header.append((Pfile.DOS_HEADER.e_cparhdr))
      self.dos_header.append((Pfile.DOS_HEADER.e_minalloc))
      self.dos_header.append((Pfile.DOS_HEADER.e_maxalloc))
      self.dos_header.append((Pfile.DOS_HEADER.e_ss))
      self.dos_header.append((Pfile.DOS_HEADER.e_sp))
      self.dos_header.append((Pfile.DOS_HEADER.e_csum))
      self.dos_header.append((Pfile.DOS_HEADER.e_ip))
      self.dos_header.append((Pfile.DOS_HEADER.e_cs))
      self.dos_header.append((Pfile.DOS_HEADER.e_lfarlc))
      self.dos_header.append((Pfile.DOS_HEADER.e_ovno))
      #dos_header.append(hex(Pfile.DOS_HEADER.e_res1))
      self.dos_header.append('0')
      self.dos_header.append((Pfile.DOS_HEADER.e_oemid))
      self.dos_header.append((Pfile.DOS_HEADER.e_oeminfo))
      #dos_header.append(hex(Pfile.DOS_HEADER.e_res2))
      self.dos_header.append('0')
      self.dos_header.append((Pfile.DOS_HEADER.e_lfanew))

      self.dos_header = [int (i) for i in self.dos_header]

      self.optional_header32=[]

      self.optional_header32.append((Pfile.OPTIONAL_HEADER.Magic))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MajorLinkerVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MinorLinkerVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfCode))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfInitializedData))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfUninitializedData))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.AddressOfEntryPoint))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.BaseOfCode))
      #optional_header32.append(hex(Pfile.OPTIONAL_HEADER.BaseOfData))
      self.optional_header32.append('0')
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.ImageBase))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SectionAlignment))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.FileAlignment))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MajorOperatingSystemVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MinorOperatingSystemVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MajorImageVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MinorImageVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MajorSubsystemVersion))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.MinorSubsystemVersion))
      #optional_header32.append(hex(Pfile.OPTIONAL_HEADER.Win32VersionValue))
      self.optional_header32.append('0')
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfImage))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfHeaders))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.CheckSum))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.Subsystem))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.DllCharacteristics))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfStackReserve))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfStackCommit))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfHeapReserve))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.SizeOfHeapCommit))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.LoaderFlags))
      self.optional_header32.append((Pfile.OPTIONAL_HEADER.NumberOfRvaAndSizes))

      self.optional_header32 = [int (i) for i in self.optional_header32]

      self.optional_header64=[]

      self.optional_header64.append((Pfile.OPTIONAL_HEADER.Magic))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MajorLinkerVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MinorLinkerVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfCode))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfInitializedData))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfUninitializedData))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.AddressOfEntryPoint))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.BaseOfCode))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.ImageBase))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SectionAlignment))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.FileAlignment))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MajorOperatingSystemVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MinorOperatingSystemVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MajorImageVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MinorImageVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MajorSubsystemVersion))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.MinorSubsystemVersion))
      #optional_header64.append(hex(Pfile.OPTIONAL_HEADER.Win32VersionValue))
      self.optional_header64.append('0')
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfImage))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfHeaders))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.CheckSum))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.Subsystem))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.DllCharacteristics))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfStackReserve))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfStackCommit))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfHeapReserve))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.SizeOfHeapCommit))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.LoaderFlags))
      self.optional_header64.append((Pfile.OPTIONAL_HEADER.NumberOfRvaAndSizes))

      self.optional_header64 = [int (i) for i in self.optional_header64]

      self.file_header=[]

      self.file_header.append((Pfile.FILE_HEADER.Machine))
      self.file_header.append((Pfile.FILE_HEADER.NumberOfSections))
      self.file_header.append((Pfile.FILE_HEADER.TimeDateStamp))
      self.file_header.append((Pfile.FILE_HEADER.PointerToSymbolTable))
      self.file_header.append((Pfile.FILE_HEADER.NumberOfSymbols))
      self.file_header.append((Pfile.FILE_HEADER.SizeOfOptionalHeader))
      self.file_header.append((Pfile.FILE_HEADER.Characteristics))

      self.file_header = [int (i) for i in self.file_header]



   def creat_split_window(self):   

      hbox = QHBoxLayout()
      
      splitter1 = QSplitter(Qt.Horizontal)

      firstSection = self.creat_tree()
      secondSection = self.display_hex()
      thirdSection = self.display_view()
      
      splitter1.addWidget(firstSection)
      splitter1.addWidget(secondSection)

      #splitter1.addWidget(hexview)
      splitter1.setSizes([300,800])

      splitter2 = QSplitter(Qt.Horizontal)
      splitter2.addWidget(splitter1)
      splitter2.addWidget(thirdSection)
      splitter2.setSizes([1500,500])

      hbox.addWidget(splitter2)
      #QApplication.setStyle(QStyleFactory.create('Cleanlooks'))
      self.setLayout(hbox)

   def display_hex(self):
      global filename
      filep = codecs.open(filename, "rb")
      offset = 0
      global filesize
      filesize = os.path.getsize(filename)
      hexview = ""

      while True:
         data = filep.read(16)
         if len(data) == 0: 
            break
         result = '0x{:08X}: '.format(offset)
         
         for i in range(len(data)):
            result += '{:02X} '.format(data[i])
         
         if len(data) != 16:
            for i in range(16 - len(data)):
               result += '   '

         for i in range(len(data)):
            if 0x20 <= data[i] <= 0x7E:
               result += chr(data[i])
            else:
               result += '.'
         result += '\n'
         hexview += result

         offset += 16

      self.Doc = QTextDocument()
      self.Doc.setPlainText(hexview)

      self.TextView = QTextEdit()
      self.TextView.setDocument(self.Doc)

      self.TextView.setFontPointSize(5)
      self.TextView.setFont(QFont("Times", 7))
      fixed_font = QFont("monospace")
      fixed_font.setStyleHint(QFont.TypeWriter)
      self.TextView.setFont(fixed_font)

      self.cursor = self.TextView.textCursor()
      self.cursor.movePosition(QTextCursor.End, QTextCursor.MoveAnchor)
      self.TextView.setTextCursor(self.cursor)
      self.TextView.show()

      return self.TextView


   def treeView_clicked2 (self, index1):
      global Pfile
      indexItem = self.treeView.selectedIndexes()[0]
      self.item = indexItem.model().itemFromIndex(indexItem)
      itemname = self.item.text()
      self.offsetStart = 0

      if itemname == "IMAGE_DOS_HEADER":
         self.offsetStart = 0
         self.size = Pfile.DOS_HEADER.sizeof()

      elif itemname == "DOS_STUB":
         self.offsetStart = 0 + Pfile.DOS_HEADER.sizeof()
         self.size = Pfile.DOS_HEADER.e_lfanew - 0

      elif itemname == "IMAGE_NT_HEADERS":
         self.offsetStart = Pfile.DOS_HEADER.e_lfanew
         self.size = Pfile.NT_HEADERS.sizeof() + Pfile.FILE_HEADER.sizeof() + Pfile.OPTIONAL_HEADER.sizeof()

      elif itemname == "Signature":
         self.offsetStart = Pfile.DOS_HEADER.e_lfanew
         self.size = 0x4

      elif itemname == "IMAGE_FILE_HEADER":
         self.offsetStart = Pfile.DOS_HEADER.e_lfanew + 0x4
         self.size = Pfile.FILE_HEADER.sizeof()

      elif itemname == "IMAGE_OPTIONAL_HEADER" or itemname == "IMAGE_OPTIONAL_HEADER64":
         self.offsetStart = Pfile.DOS_HEADER.e_lfanew + 0x4 + Pfile.FILE_HEADER.sizeof()
         self.size = Pfile.OPTIONAL_HEADER.sizeof()

      elif itemname == "IMAGE_DATA_DIRECTORY":
         self.offsetStart = Pfile.DOS_HEADER.e_lfanew + 0x4 + Pfile.FILE_HEADER.sizeof() + Pfile.OPTIONAL_HEADER.sizeof() - 16*8     
         self.size = 16*8

      elif itemname == "IMPORT_TABLE":
         self.offsetStart = Pfile.DOS_HEADER.e_lfanew + 0x4 + Pfile.FILE_HEADER.sizeof() + Pfile.OPTIONAL_HEADER.sizeof() - 16*8 + 8
         self.size = 8

     


      i = 0
      for section in Pfile.sections:
         if itemname == ("IMAGE_SECTION_HEADER_" + section.Name.decode('utf-8')):
            self.offsetStart = int(Pfile.DOS_HEADER.e_lfanew) + 0x4 + Pfile.FILE_HEADER.sizeof() + 40*i
            self.size = 40
         i+=1

         if itemname == ("SECTION_" + section.Name.decode('utf-8')):
            self.offsetStart = Pfile.get_offset_from_rva(section.VirtualAddress)      
            self.size = section.SizeOfRawData

      i = 0
      for field in Pfile.DIRECTORY_ENTRY_IMPORT :
        if itemname == ("IMAGE_IMPORT_DESCRIPTOR" + str(i)):
          self.offsetStart = Pfile.get_offset_from_rva(Pfile.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress) + 20*i
          self.size = 20
        i += 1



      self.move_hex_line(self.offsetStart, self.size)
      

   def move_hex_line(self, offset, size):
      global filesize
      offset = int(offset/0x10)
      self.cursor.movePosition(QTextCursor.End, QTextCursor.MoveAnchor)
      for i in range(int(filesize/0x10)-offset):
         self.cursor.movePosition(QTextCursor.Up)
         self.TextView.setTextCursor(self.cursor)
      #print(offset, size)
      
      



   def creat_tree(self):
      QWidget.__init__(self)
      global filename

      self.treeView = QTreeView()
      self.model = QStandardItemModel()
      self.rootNode = self.model.invisibleRootItem()

      self.read_tree()
           
      self.treeView.setEditTriggers(QAbstractItemView.NoEditTriggers)
      self.treeView.setModel(self.model)
           
      self.model.setHorizontalHeaderLabels([self.tr(filename)])
      self.treeView.clicked.connect(self.treeView_clicked)
      self.treeView.clicked.connect(self.treeView_clicked2)

      return self.treeView
   
   def read_tree(self):
      global Pfile
      self.ImageDosHeader = QStandardItem(Pfile.DOS_HEADER.name)
      self.DosStub = QStandardItem("DOS_STUB")
      self.ImageNtHeader = QStandardItem(Pfile.NT_HEADERS.name)
      self.ImageNtHeader.appendRow([QStandardItem("Signature")])
      self.ImageNtHeader.appendRow([QStandardItem(Pfile.FILE_HEADER.name)])
      
      self.OptionalHeader = QStandardItem(Pfile.OPTIONAL_HEADER.name)
      
      self.ImageDataDirectory = QStandardItem("IMAGE_DATA_DIRECTORY")
      self.ImageDataDirectory.appendRow([QStandardItem("EXPORT_TABLE")])

      self.IMPORT_TABLE = QStandardItem("IMPORT_TABLE")

      i = 0
      IMAGE_IMPORT_DESCRIPTOR = []
      for field in Pfile.DIRECTORY_ENTRY_IMPORT :
         IMAGE_IMPORT_DESCRIPTOR.append("IMAGE_IMPORT_DESCRIPTOR" + str(i))
         i+=1

      i = 0
      for field in Pfile.DIRECTORY_ENTRY_IMPORT :
         IMAGE_IMPORT_DESCRIPTOR[i] = QStandardItem("IMAGE_IMPORT_DESCRIPTOR"+ str(i))
         self.IMPORT_TABLE.appendRow(IMAGE_IMPORT_DESCRIPTOR[i])
         i+=1

      self.ImageDataDirectory.appendRow(self.IMPORT_TABLE)
      
      self.ImageDataDirectory.appendRow([QStandardItem("RESOURCE_TABLE")])
      self.ImageDataDirectory.appendRow([QStandardItem("EXCEPTION_TABLE")])
      self.ImageDataDirectory.appendRow([QStandardItem("CERTIFICATE_TABLE")])
      self.ImageDataDirectory.appendRow([QStandardItem("BASE_RELOCATION_TABLE")])
      self.ImageDataDirectory.appendRow([QStandardItem("DEBUG")])
      self.ImageDataDirectory.appendRow([QStandardItem("ARCHITECTURE")])
      self.ImageDataDirectory.appendRow([QStandardItem("GLOBAL_PTR")])
      self.ImageDataDirectory.appendRow([QStandardItem("TLS_TABLE")])
      self.ImageDataDirectory.appendRow([QStandardItem("LOAD_CONFIG_TABLE")])
      self.ImageDataDirectory.appendRow([QStandardItem("BOUND_IMPORT")])
      self.ImageDataDirectory.appendRow([QStandardItem("IAT")])
      self.ImageDataDirectory.appendRow([QStandardItem("DELAY_IMPORT_DESCRIPTOR")])
      self.ImageDataDirectory.appendRow([QStandardItem("CLR_RUNTIME_HEADER")])

      self.OptionalHeader.appendRow(self.ImageDataDirectory)

      
      self.ImageNtHeader.appendRow(self.OptionalHeader)
      
      
      self.rootNode.appendRow([self.ImageDosHeader])
      self.rootNode.appendRow([self.DosStub])
      self.rootNode.appendRow([self.ImageNtHeader])
      

      self.SectionHeader = {}
      num = 0
      for section in Pfile.sections:
         data = "IMAGE_SECTION_HEADER_"
         #data += str(section.Name)[2:str(section.Name).find('\\')]
         data += str(section.Name.decode('utf-8'))
         self.SectionHeader[num] = QStandardItem(data)
         self.rootNode.appendRow([self.SectionHeader[num]])
         num += 1
      
      self.Section = {}
      num = 0
      for section in Pfile.sections:
         data = "SECTION_"
         #data += str(section.Name)[2:str(section.Name).find('\\')]
         data += str(section.Name.decode('utf-8'))
         self.Section[num] = QStandardItem(data)
         self.rootNode.appendRow([self.Section[num]])
         num += 1


   def treeView_clicked (self, index1):
      indexItem = self.treeView.selectedIndexes()[0]
      self.item = indexItem.model().itemFromIndex(indexItem)
      filename = self.item.text()
      self.change_view(filename)


   def display_view(self):
      self.vhtml = QWebView()
      self.peInformationToList()
      self.change_view()
      #self.vhtml.resize(100,400)
      self.vhtml.show()

      return self.vhtml

   def change_view(self, filename = "initial"):
      filename = "./html/" + filename

      filename = filename.replace('\x00', "")
      filename +=".html"

      fhtml = open(filename,'r')
      if not fhtml:
         fhtml = codecs.open("./html/file_open_error.html",'r')
         print("file open error")
      
      data = fhtml.read()
      data = self.insertValue(filename,data)
      fhtml.close()
      self.vhtml.setHtml(data)
      

   def insertValue(self, filename, data):
      global Pfile

      if filename == "./html/IMAGE_DOS_HEADER.html":
         # print(self.dos_header)
         # print(self.offsetStart)
         # print(self.size)
         data = data.format(self.offsetStart, self.size, x = self.dos_header)


      elif filename == "./html/DOS_STUB.html":
        data = data.format(self.offsetStart, self.size)

      elif filename == "./html/IMAGE_NT_HEADERS.html":
        data = data.format(self.offsetStart, self.size)

      elif filename == "./html/Signature.html":
        data = data.format(self.offsetStart, self.size)

      elif filename == "./html/IMAGE_FILE_HEADER.html":
        data = data.format(self.offsetStart, self.size, x = self.file_header)

      elif filename == "./html/IMAGE_OPTIONAL_HEADER.html":
        data = data.format(self.offsetStart, self.size, x = self.optional_header32)

      elif filename == "./html/IMAGE_OPTIONAL_HEADER64.html":
        data = data.format(self.offsetStart, self.size, x = self.optional_header64)

      elif filename == "./html/IMAGE_DATA_DIRECTORY.html":
        data = data.format(self.offsetStart, self.size)



      i = 0
      for field in Pfile.DIRECTORY_ENTRY_IMPORT :
        if filename == ("./html/IMAGE_IMPORT_DESCRIPTOR" + str(i) + ".html"):
          #print(1)
          importNameList = []
          importCount = len(Pfile.DIRECTORY_ENTRY_IMPORT[i].imports)

          for importI in range(0, importCount):
            #print(importI)
            importNameList.append(Pfile.DIRECTORY_ENTRY_IMPORT[i].imports[importI].name)
          #print(importNameList)
          data += "<br><strong>" + str((Pfile.DIRECTORY_ENTRY_IMPORT[i].dll).decode('utf-8')) + " : </strong><br>"
          for importI in importNameList:
            data += str(importI.decode('utf-8')) + "<br>"
          data += "</body></html>"
          data = data.format(self.offsetStart, self.size)
        #print(filename)
        i += 1
        




      for section in Pfile.sections:
        if filename == ("./html/IMAGE_SECTION_HEADER_" + section.Name.decode('utf-8')+ ".html").replace('\x00', ""):
          data = data.format(self.offsetStart, self.size)
          #print(self.offsetStart, self.size)
         
      for section in Pfile.sections:
        #print(1)
        if filename == ("./html/SECTION_" + str(section.Name.decode('utf-8')) + ".html").replace('\x00', ""):
          #print("AAAAA")
          data = data.format(self.offsetStart, self.size)


      


      return data

if __name__ == '__main__':
   app = QApplication(sys.argv)
   ex = MyWindow()
   sys.exit(app.exec_())