import glob
# Copyright 2022 by Minh Nguyen. All rights reserved.
#     @author Minh Tu Nguyen
#     @email  nmtu.mia@gmail.com
# 
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from worker.base.silentworker_base import SilentWorkerBase
from utils.utils import log
import os
from main.rep2graph import Rep2Graph


class SilentWorker(SilentWorkerBase):
    """
    This is the baseline for the SilentWorker.

    SilentWorker should be the one carrying the main work.
    Sometimes a module might take a great deal of time to generate outputs. 

    Whenever your model finishes an operation, make sure to call `__onFinish__` function to populate your results to db as well as to the next module in the chain.
        Command:
            self.__onFinish__(output[, note])

        whereas:
            - output (mandatory): A dict that maps a `orig_input_hash` => output
                Output could be of any type. Just make sure to note that in your module's configuration and description for others to interpret your results.
                For example,
                    - a detector module can return a boolean (to represent detection result).
                    - a non-detector module (eg. processor or sandbox) can return the path storing processed result.
                eg.
                    {
                        'hash_of_input_1': true,
                        'hash_of_input_2': false,
                        'hash_of_input_3': false,
                        ...
                    }
            - note (optional).
                It could be a dict or a string.
                If it's a dict, it must be a map of a filepath to a note (string). The system will find and save the note accordingly with the file. 
                If it's not a map, use a string. The system will save this note for all the files analyzed in this batch
    """

    def __init__(self, config) -> None:
        """ Dont change/remove this super().__init__ line.
            This line passes config to initialize services. 
        """
        super().__init__(config)

        #! Add your parts of initializing the model or anything you want here. 
        #! You might want to load everything at this init phase, not reconstructing everything at each request (which shall then be defined in run())
        print('Nooby doo')
        self.obj_r2g = Rep2Graph()
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

    
    def onChangeConfig(self, config_data):
        """
        Callback function when module's config is changed.
        (usually at each request to analyze, when config_data is sent along as a parameter)
        ---
        This is the module's config which is passed at each analysis request. (usually the config to initialize the model)
        """

        log(f'[ ][SilentWorker][onChangeConfig] config_data is passed: {config_data}')

        #! Want to do something with the model when the config is changed ? Maybe reconfig the model's params, batch size etc. ?
        #? eg. change global module's config
        #self._config = config_data
        #? let my main module decide
        
        return


    def infer(self, config_data):
        """
        #? This function is to be overwritten.
        Main `inference` function. 

            #? (used for all modules, `detector`, `(pre)processor`, `sandbox`)
            Whatever you need to do in silence, put it here.
            We provide inference in batch, for heavy models.

        ----
        Use these vars to access input data:
            - self._map_ohash_inputs: dict of inputs to feed this module (eg. filepath to the executable files already stored on the system / url).
                map `orig_input_hash` => `prev module's output for orig_path correspond with orig_input_hash`
            - self._map_ohash_oinputs: dict of original inputs that is fed to this module flow.
                map `orig_input_hash` => one `orig_path`.
                (multiple orig_path might have the same hash, but just map to one path)
        
        Params:
            - config_data: modules configuration stored in the db.
        """

        try:
        # if True: #? to debug
            #! Do something
            log('[ ][SilentWorker][infer] I\'m pretty')
            
            result = {}
            note ={}
            for ohash,inputs in self._map_ohash_inputs.items():
                filepath = inputs[1]
                log(f'[ ] ohash : {ohash}  |  filepath : {filepath}')
                stt = self.obj_r2g.r2g(filepath, '', ohash, None, self.dir_out_report_cut, self.dir_out_nx, self.dir_out_graphviz, render_svg=True)
                if stt is True:
                    #? dot file
                    # report_name = os.path.basename(filepath)
                    dot_file = os.path.join(self.dir_out_graphviz, f'{ohash}.dot')
                    svg_file = os.path.join(self.dir_out_graphviz, f'{ohash}.dot.svg')

                    #! After finish, clean up and return data in appropriate format
                    result[ohash] = [svg_file, dot_file]


            #! Call __onFinishInfer__ when the analysis is done. This can be called from anywhere in your code. In case you need synchronous processing
            self.__onFinishInfer__(result, note)

        except:
            log('[x][SilentWorker][infer] Ouch', 'error')
            return
