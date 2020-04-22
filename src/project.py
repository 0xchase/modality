import angr
import claripy

class Project():
    def __init__(self, filename):
        self.filename = filename
        self.project = angr.Project(self.filename)
        #self.state = self.project.factory.entry_state(add_options=angr.options.unicorn)
        self.state = self.project.factory.entry_state()
        self.simgr = self.project.factory.simgr(self.state)
