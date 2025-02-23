import sys
import hashlib
import itertools
import string
import numpy as np
from functools import lru_cache
from multiprocessing import Pool, cpu_count
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, 
                             QLineEdit, QLabel, QComboBox, QSpinBox, QProgressBar, QTextEdit, 
                             QFileDialog, QRadioButton, QHBoxLayout)

# Dfinition des ensembles de caracteres
letters = string.ascii_letters
numbs = string.digits
punc = string.punctuation
let_punc = letters + punc
numbs_punc = numbs + punc
let_nums = letters + numbs
all_characters = letters + numbs + punc

# Fonction pour utiliser les Rainbow Tables (Pr-calcul)
import sqlite3
def check_rainbow_table(hash_target):
    conn = sqlite3.connect("rainbow_table.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM hashes WHERE hash=?", (hash_target,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Gnration rapide des combinaisons avec numpy
def fast_bruteforce(charset, length):
    return np.random.choice(list(charset), size=length)

# Worker utilisant multiprocessing
def brute_force_worker(start_len, end_len, charset, hash_target, hash_function):
    for length in range(start_len, end_len + 1):
        for attempt in itertools.product(charset, repeat=length):
            candidate = ''.join(attempt)
            candidate_hash = hashlib.new(hash_function, candidate.encode()).hexdigest()
            if candidate_hash == hash_target:
                return candidate
    return None

class Worker(QThread):
    result_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    log_signal = pyqtSignal(str)

    def __init__(self, hash_target, hash_function, charset, max_len, num_threads, attack_type, dict_files):
        super().__init__()
        self.hash_target = hash_target
        self.hash_function = hash_function
        self.charset = charset
        self.max_len = max_len
        self.num_threads = num_threads
        self.attack_type = attack_type
        self.dict_files = dict_files

    def run(self):
        if self.attack_type == "brute_force":
            # Utilisation de multiprocessing
            step = self.max_len // self.num_threads
            pool = Pool(cpu_count())  
            tasks = []
            for i in range(self.num_threads):
                start_len = i * step + 1
                end_len = (i + 1) * step if i != self.num_threads - 1 else self.max_len
                tasks.append(pool.apply_async(brute_force_worker, (start_len, end_len, self.charset, self.hash_target, self.hash_function)))
            pool.close()
            pool.join()

            for task in tasks:
                result = task.get()
                if result:
                    self.result_signal.emit(f"Found: {result}")
                    return
            self.result_signal.emit("Failed to find the password within the given length.")
        elif self.attack_type == "dictionary":
            self.dictionary_attack()

    def dictionary_attack(self):
        """Lit un ou plusieurs fichiers de dictionnaire pour essayer les mots de passe."""
        for file in self.dict_files:
            try:
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        candidate = line.strip()
                        candidate_hash = hashlib.new(self.hash_function, candidate.encode()).hexdigest()
                        if candidate_hash == self.hash_target:
                            self.result_signal.emit(f"Found: {candidate}")
                            return
            except Exception as e:
                self.log_signal.emit(f"Error reading {file}: {str(e)}")
        
        self.result_signal.emit("Password not found in dictionary.")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Brute Force & Dictionary Hash Cracker")
        self.setGeometry(100, 100, 700, 500)

        self.initUI()

    def initUI(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        layout = QVBoxLayout(self.central_widget)

        self.hash_input = QLineEdit(self)
        self.hash_input.setPlaceholderText("Enter your hash")
        layout.addWidget(self.hash_input)

        self.hash_algo = QComboBox(self)
        self.hash_algo.addItems(["md5", "sha1", "sha256"])
        layout.addWidget(self.hash_algo)

        self.brute_force_radio = QRadioButton("Brute Force Attack")
        self.dict_attack_radio = QRadioButton("Dictionary Attack")
        self.brute_force_radio.setChecked(True)
        layout.addWidget(self.brute_force_radio)
        layout.addWidget(self.dict_attack_radio)

        self.attack_type_combo = QComboBox(self)
        self.attack_type_combo.addItems([
            "Letters only", "Numbers only", "Letters & Numbers",
            "Letters & Punctuation", "Numbers & Punctuation", "All Characters"
        ])
        layout.addWidget(self.attack_type_combo)

        self.max_length_input = QSpinBox(self)
        self.max_length_input.setMinimum(1)
        self.max_length_input.setMaximum(20)
        self.max_length_input.setValue(6)
        layout.addWidget(QLabel("Maximum password length"))
        layout.addWidget(self.max_length_input)

        self.thread_count_input = QSpinBox(self)
        self.thread_count_input.setMinimum(1)
        self.thread_count_input.setMaximum(16)
        self.thread_count_input.setValue(4)
        layout.addWidget(QLabel("Number of threads"))
        layout.addWidget(self.thread_count_input)

        self.choose_dict_button = QPushButton("Choose Dictionary Files")
        self.choose_dict_button.clicked.connect(self.select_dictionaries)
        layout.addWidget(self.choose_dict_button)

        self.dict_files_label = QLabel("No dictionaries selected")
        layout.addWidget(self.dict_files_label)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

        self.start_button = QPushButton("Start Attack", self)
        self.start_button.clicked.connect(self.start_attack)
        layout.addWidget(self.start_button)

        self.result_label = QLabel("", self)
        layout.addWidget(self.result_label)

        self.log_output = QTextEdit(self)
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.central_widget.setLayout(layout)

        self.dict_files = []

    def select_dictionaries(self):
        """Ouvre un dialogue pour choisir plusieurs fichiers de dictionnaire."""
        files, _ = QFileDialog.getOpenFileNames(self, "Select Dictionary Files", "", "Text Files (*.txt);;All Files (*)")
        if files:
            self.dict_files = files
            self.dict_files_label.setText(f"Selected: {', '.join(files)}")
        else:
            self.dict_files_label.setText("No dictionaries selected")

    def start_attack(self):
        given_hash = self.hash_input.text()
        hash_algo = self.hash_algo.currentText()
        attack_type = "brute_force" if self.brute_force_radio.isChecked() else "dictionary"
        max_length = self.max_length_input.value()
        num_threads = self.thread_count_input.value()
        charset = self.select_charset(self.attack_type_combo.currentIndex() + 1)

        if attack_type == "dictionary" and not self.dict_files:
            self.log_output.append("Please select at least one dictionary file for dictionary attack.")
            return

        self.worker = Worker(given_hash, hash_algo, charset, max_length, num_threads, attack_type, self.dict_files)
        self.worker.result_signal.connect(self.display_result)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.log_signal.connect(self.update_log)
        self.worker.start()

    def select_charset(self, attack_type):
        dictionary = {1: letters, 2: numbs, 3: let_nums, 4: let_punc, 5: numbs_punc, 6: all_characters}
        return dictionary.get(attack_type, all_characters)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def update_log(self, log_entry):
        self.log_output.append(log_entry)

    def display_result(self, result):
        self.result_label.setText(result)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
