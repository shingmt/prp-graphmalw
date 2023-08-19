from worker.base.silentworker_base import SilentWorkerBase
from utils.utils import log
import os
from main.rep2graph import Rep2Graph


class Test:
    def __init__(self) -> None:
        self.obj_r2g = Rep2Graph()
        self.module_outdir = './'
        self.dir_out_report_cut = os.path.join(self.module_outdir, 'json')
        self.dir_out_nx = os.path.join(self.module_outdir, 'nx')
        self.dir_out_graphviz = os.path.join(self.module_outdir, 'graphviz')
        self.dir_out_graph = os.path.join(self.module_outdir, 'graphs')
        if not os.path.isdir(self.dir_out_report_cut):
            os.makedirs(self.dir_out_report_cut)
        if not os.path.isdir(self.dir_out_nx):
            os.makedirs(self.dir_out_nx)
        if not os.path.isdir(self.dir_out_graphviz):
            os.makedirs(self.dir_out_graphviz)
        if not os.path.isdir(self.dir_out_graph):
            os.makedirs(self.dir_out_graph)


    def test(self, filepath) -> None:
        stt = self.obj_r2g.r2g(filepath, '', None, self.dir_out_report_cut, self.dir_out_nx, self.dir_out_graphviz, render_svg=True)
        return


if __name__ == '__main__':
    tcls = Test()
    path = './data/7717.json'
    tcls.test(path)