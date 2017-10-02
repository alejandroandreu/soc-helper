from PyQt5 import QtCore, QtGui, QtWidgets
from ui import Ui_MainWindow
import provider, utils, sys, os

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
        # self.ip_search_button.clicked.connect(self.go)
        # self.ip_search_input.returnPressed.connect(self.go)

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
                    "url": self.url_tab
                    }
            tab = tab_switcher.get(key)
            provider_zone_switch = {
            		"ip": self.ip_providers,
            		"url": self.url_providers
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
        for i in ["ip", "url"]:
            providers[i] = []
            provider_configs_folder = provider_dir + "/" + i
            provider_configs = os.listdir(provider_configs_folder)
            for pc_file in provider_configs:
                pc_full_path = provider_configs_folder + "/" + pc_file
                providers[i].append(provider.create(provider.ProviderConfig(pc_full_path)))
        return providers

    def go(self, tab):
        """
        Checks which checkboxes are marked in a given tab, then gets a
        valid URL for each one of them.
        """
        pass



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    main_window = QtWidgets.QMainWindow()
    prog = HelperGUI(main_window)
    main_window.show()
    sys.exit(app.exec_())
