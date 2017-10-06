from PyQt5 import QtCore, QtGui, QtWidgets
from ui import Ui_MainWindow
import provider, utils, sys, os, webbrowser

class HelperGUI(Ui_MainWindow):
    """
    Wrapper around the GUI generated by Qt Designer.
    """
    def __init__(self, main_window):
        # Load the main view
        Ui_MainWindow.__init__(self)
        self.setupUi(main_window)

        # Load providers for each type of resource
        self.providers = self.load_providers("../providers")
        self.checks = {}
        self.draw_checkboxes(self.providers)

        # Tie input fields and "Go" buttons to functions
        self.ip_search_button.clicked.connect(self.goip)
        self.ip_search_input.returnPressed.connect(self.goip)
        self.url_search_button.clicked.connect(self.gourl)
        self.url_search_input.returnPressed.connect(self.gourl)
        self.file_search_button.clicked.connect(self.gourl)
        self.file_search_input.returnPressed.connect(self.gourl)

    def popup(self, title, message):
        """
        Display a popup with the given message
        """
        QtWidgets.QMessageBox.about(main_window, title, message)

    def draw_checkboxes(self, providers):
        """
        Iterate over providers and load checkboxes on every tab accordingly.
        """
        _translate = QtCore.QCoreApplication.translate
        for key in providers.keys():
            self.checks[key] = {}
            names = []
            tab_switcher = {
                    "ip": self.ip_tab,
                    "url": self.url_tab,
                    "file": self.file_tab
                    }
            tab = tab_switcher.get(key)
            provider_zone_switch = {
                    "ip": self.ip_providers,
                    "url": self.url_providers,
                    "file": self.file_providers
                    }
            provider_zone = provider_zone_switch.get(key)
            # Load provider names in an array first
            for provider in providers[key]:
                names.append(provider.name)
            # Render the checkboxes later
            check_counter = 0
            row = 0
            col = 0
            for name in names:
                self.checks[key][name] = QtWidgets.QCheckBox(tab)
                self.checks[key][name].setObjectName(name)
                provider_zone.addWidget(self.checks[key][name], row, col, 1, 1)
                self.checks[key][name].setText(_translate("MainWindow", name))
                check_counter += 1
                col = check_counter % utils.MAX_CHECKS_COLS
                if col == 0:
                    row += 1

    def load_providers(self, provider_dir):
        providers = {}
        # TODO: Enable the rest of the providers
        for i in ["ip", "url", "file"]:
            providers[i] = []
            provider_configs_folder = provider_dir + "/" + i
            provider_configs = os.listdir(provider_configs_folder)
            for pc_file in provider_configs:
                pc_full_path = provider_configs_folder + "/" + pc_file
                providers[i].append(provider.create(provider.ProviderConfig(pc_full_path)))
        return providers

    # TODO: Unify all "go" functions
    def goip(self):
        """
        Checks which checkboxes are marked in the IP tab, then gets a
        valid URL for each one of them.
        """
        active_checks = []
        for check in self.checks["ip"].values():
            if check.checkState() == 2:
                active_checks.append(check)

        self.open_pages("ip", active_checks)

    def gourl(self):
        """
        Checks which checkboxes are marked in the IP tab, then gets a
        valid URL for each one of them.
        """
        active_checks = []
        for check in self.checks["url"].values():
            if check.checkState() == 2:
                active_checks.append(check)

        self.open_pages("url", active_checks)

    def gofile(self):
        """
        Checks which checkboxes are marked in the IP tab, then gets a
        valid URL for each one of them.
        """
        active_checks = []
        for check in self.checks["file"].values():
            if check.checkState() == 2:
                active_checks.append(check)

        self.open_pages("file", active_checks)

    def open_pages(self, section, checks):
        input_switch = {
                "ip": self.ip_search_input.text(),
                "url": self.url_search_input.text(),
                "url": self.file_search_input.text()
                }
        input_value = input_switch.get(section)
        if input_value == '':
            return False
        # Find what provider corresponds to what marked check and append it
        marked_providers = []
        for check in checks:
            check_name = check.objectName()
            for provider in self.providers[section]:
                if check_name == provider.name:
                    marked_providers.append(provider)

        # Execute get_url() on every provider and update progress bar
        generated_urls = 1
        urls = []
        for provider in marked_providers:
            urls.append(provider.get_url(input_value))
            progress = (generated_urls / len(marked_providers)) * 100
            self.progressBar.setValue(progress)
            generated_urls += 1

        for url in urls:
            webbrowser.open(url)

        # Reset progress bar
        self.progressBar.setValue(0)



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    main_window = QtWidgets.QMainWindow()
    prog = HelperGUI(main_window)
    main_window.show()
    sys.exit(app.exec_())
