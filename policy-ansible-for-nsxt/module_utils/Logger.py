class Logger(object):
    __instance = None

    def __init__(self):
        self.logfile = '/root/ansible-for-nsxt/' + \
            'policy-ansible-for-nsxt/logs/log'
        if Logger.__instance is not None:
            raise Exception("This class is a singleton!")
        else:
            Logger.__instance = self
        with open(self.logfile, 'w+'):
            pass

    @staticmethod
    def getInstance():
        if Logger.__instance is None:
            Logger()
        return Logger.__instance

    def log(self, data):
        with open(self.logfile, 'a') as f:
            f.write(data)
            f.write('\n')
