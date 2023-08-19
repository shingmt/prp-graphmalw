import copy
import os
import json
from graphviz import Source
import networkx as nx
import matplotlib.pyplot as plt
from utils.utils import log


class Rep2Graph:
    do_limit_cat = True
    limit_cats = ['process', 'file', 'registry', 'system']
    # limit_cats = ['system']
    # limit_cats = ['process']

    do_limit_edge = False
    # limit_etypes = ['proc-api', 'api-proc', 'api-nproc', 'api-api']
    limit_etypes = ['proc-api', 'api-nproc', 'api-api', 'api-proc', 'api-handle', 'handle-api', 'api-module', 'module-api', 'api-file_handle', 'file_handle-api', 'api-key_handle', 'key_handle-api']
    # limit_etypes = ['proc-api', 'api-proc', 'api-nproc', 'api-api', 'api-handle']
    # limit_etypes = ['proc-api', 'api-api', 'api-proc']

    do_limit_api = True
    # exclude_apis = ['NtQueryKey']
    
    """ Types of node """
    n_types = [
        'proc',     #? process
        'api',      #? api call
        'handle',   #? a handle. thread_handle, file_handle, key_handle (registry), module_handle
        'key_handle',
        'file_handle',
        'module',   #? a module address, which is the actual function that the api calls (when api is LdrLoadDll or LdrGetProcedureAddress)
    ]
    """ Types of edge """
    e_types = [
        'proc-api',     #? connects a process to an api, shows that this process makes the first call to this api
        'api-proc',     #? connects an api to the same process that calls it, shows that this api is doing something with this process (normally sees this with NtCreateThreadEx, NtAllocateVirtualMemory, NtMapViewOfSection, NtResumeThread, ...)
        'api-nproc',    #? connects an api to another process, shows that this api spawns a new process (this proc)
        'api-api',      #? connects 2 api, creates a sequence of api calls
        'api-handle',   #? connects an api to a handle, shows that the api affects the handle
        'handle-api',   #? connects an api with a handle, shows that the api get info from the handle to affect other handle
        'api-key_handle',
        'key_handle-api',
        'api-file_handle',
        'file_handle-api',
        'api-module',    #? connects an api to a module, when an api gets the address of a dll
        'module-api'    #? connects a module to an api, when an api uses the address of a loaded dll to get the address of a function to use that function
    ]
    map_ntype2style = {
        'api': {
            'shape': 'box',
            'style': '',
            'color': 'gray',
            'fillcolor': '#3232322d', 
            'fontcolor': '#323232ed' 
        },
        'proc': {
            'shape': 'octagon',
            'style': 'filled',
            'color': 'black',
            'fillcolor': '#3c00783d', # purple
            'fontcolor': '#3c0078'
        },
        'handle': {
            'shape': 'oval',
            'style': 'filled',
            'color': 'black',
            'fillcolor': '#e32c103d',
            'fontcolor': '#e32c10'
        },
        'key_handle': {
            'shape': 'oval',
            'style': 'filled',
            'color': 'black',
            'fillcolor': '#d923ca3d',
            'fontcolor': '#d923ca'
        },
        'file_handle': {
            'shape': 'oval',
            'style': 'filled',
            'color': 'black',
            'fillcolor': '#1a28eb3d',
            'fontcolor': '#1a28eb'
        },
        'module': {
            'shape': 'component',
            'style': 'filled',
            'color': 'black',
            'fillcolor': '#1a91403d',
            'fontcolor': '#1a9140'
        }
    }
    map_etype2style = {
        'proc-api': '#323232ff', # black
        'api-api': '#32323268', # black
        'api-proc': '#3c007888', # purple
        'api-nproc': '#38aba9aa', # cyan
        'api-handle': '#e32c1088', # red
        'handle-api': '#e32c1088', # red
        # 'handle-api': '#f5958788', # light red
        'api-key_handle': '#d923ca88', # pink
        'key_handle-api': '#d923ca88', # pink
        # 'key_handle-api': '#e381db88', # light pink
        'api-file_handle': '#1a28eb88', # blue
        'file_handle-api': '#1a28eb88', # blue
        # 'file_handle-api': '#5963f088', # light blue
        'api-module': '#1a914088', # green
        'module-api': '#1a914088', # green
        # 'module-api': '#5ff58f88', # light green
    }


    def __init__(self, config=None):
        # self.dir_log = config['dir_log']
        self.hard_reset()
        self.reset()
        return
    

    def hard_reset(self) -> None:
        self.logfile = 'r2g.log'
        open(self.logfile, 'w').write('')

        self.reset()
        
        return


    def reset(self) -> None:
        """
        Reset graph attribute and everything, to construct other graph.
        Call this before constructing any graph
        """

        self.apis = [] #? store all apis that are considered

        #? keep track of current working report / current graph (use graph_name (= {label}__{report_name}) to set value for self.current_graph)
        self.current_graph = ''
        self.current_graph_label = ''

        #? keep track of what nodes / edges have been added to the working graph
        #? map a node identifier string (eg. {type}__{name}) to its node idx
        self.map_nodestr_node = {}
        self.map_nodestr_nodetype = {}
        self.map_nodestr_node_by_type = {n_type: {} for n_type in self.n_types}
        #? map an edge identifier string ({s_node_idx}--{d_node_idx}) to its edge idx
        self.map_edgestr_edge = {}
        self.map_edgestr_edgetype = {}
        self.map_edgestr_edge_by_type = {e_type: {} for e_type in self.e_types}

        self.map_procpath_pid = {} #? map process path to process pid. Since when adding a proc node to the graph, we use the pid only. But when an api calls to a module which is this process, it will use the process path (actually program path). To know if this process already in the nodes 

        self.map_addr_path = {} #? map an address to a filepath/regkey
        self.map_nodeid_nrels = {} #? map a node id to its number of connections 

        """ for visualization """
        self.Gx = nx.DiGraph()
        self.Gx_nodes = {}
        
        self.g_codes = {
            'nodes': {},
            'edges': {}
        } #? store lines for graphviz visualization

        return



    def read_report(self, report_file_path):
        """
        Read reports generated by Cuckoo
        and extract behaviors from behavior key
        """
        log(f'\n\n=====================================================\n\n[Rep2Graph][read_report] {report_file_path}')

        with open(report_file_path) as json_file:
            data = json.load(json_file)
            print(data)
            if 'behavior' in data.keys():
                return data['behavior']
            else:
                log('\t No behavior tag found.')
                return None


    def r2g(self, report_file_path, label, report_file_name=None, log_dir=None, report_cut_out_dir=None, nx_png_out_dir=None, dot_out_dir=None, render_svg=False):
        """
        Main function for converting from Cuckoo reports to GraphViz graph.
        - Reset
        - Read report
        - Encode report
        """
        self.reset()

        behavior = self.read_report(report_file_path)
        
        if behavior is not None:
            log('[Rep2Graph][r2g] Processing...')
            if report_file_name is None:
                report_file_name = os.path.basename(report_file_path)
            return self.encode_report(behavior, report_file_name, label, log_dir, report_cut_out_dir, nx_png_out_dir, dot_out_dir, render_svg)
        else:
            log('[Rep2Graph][r2g] Behavior none. Skip')
            return False
    

    def get_node_name(self, node):
        n_type = node['type']
        n_name = str(node['name']).lower()

        node_identifier_str = '{}__{}'.format(n_type, n_name.replace('\\', '__'))

        if 'handle' in n_type:
            node_identifier_str = '{}__{}'.format(n_type, node['address'])

        # n_name = n_name.replace('.dll', '') #? so that kernel32.dll == kernel32 ...
        if '\\' in n_name:
            n_name = n_name.split('\\')[-1] #? so that c:\windows\system32\imm32 == imm32 ...
        # if '\\' in n_name:
        #     n_name = n_name.replace('\\', '__') #? so that c:\windows\system32\imm32 == imm32 ...

        return n_name, node_identifier_str
    

    def insert_node(self, node):
        """
        Insert node with specific type.
        Arguments:
            - node: a dict of node attribute
                {
                    (mandatory) name: str,
                    (mandatory) type: str, (api | handle | module)
                    (optional)...
                }
        Returns:
            node_idx
        --------------------------------------
        One note is that sometimes process_handle would be 0xffffffff, or 0x00000000, which obviously makes no sense.
        So let's check if is all ffff, if it is, do NOT insert it as a node
        """

        n_type = node['type']


        """ If the node is not in the limited list to process, skip it """        
        if n_type not in self.n_types:
            return None


        n_name, node_identifier_str = self.get_node_name(node)


        """ Sometimes node will not be inserted to the graph. When? These. """
        if n_name == '':
            # log('Node must not have empty name value. Skip.')
            return None

        n_handle_adr = None
        if n_name[:2] == '0x':
            n_handle_adr = n_name[2:]
            la = len(n_handle_adr)
            if n_name == '0' or (n_handle_adr is not None and (n_handle_adr == '0'*la or n_handle_adr == 'f'*la)):
                return None
        

        """ Where we add the node to the graph """
        if node_identifier_str not in self.map_nodestr_nodetype.keys():
            node_idx = len(self.map_nodestr_nodetype)
            node['id'] = node_idx
            node['graph'] = self.current_graph
            node['graph_label'] = self.current_graph_label
            self.map_nodestr_nodetype[node_identifier_str] = n_type
            self.map_nodestr_node_by_type[n_type][node_identifier_str] = node

            """ for visualization """
            n_shape = self.map_ntype2style[n_type]['shape']
            n_style = self.map_ntype2style[n_type]['style']
            n_color = self.map_ntype2style[n_type]['color']
            n_fillcolor = self.map_ntype2style[n_type]['fillcolor']
            n_fontcolor = self.map_ntype2style[n_type]['fontcolor']
            #? Graphviz graph
            # n_txt = f'{node_idx} {node_identifier_str}'
            n_txt = '{} {}'.format(node_idx, node['address']) if 'handle' in node['type'] else f'{node_idx} {node_identifier_str}'
            self.g_codes['nodes'][node_idx] = f'node [shape="{n_shape}" style="{n_style}" color="{n_color}" fontcolor="{n_fontcolor}" fillcolor="{n_fillcolor}"] {node_idx} [label="{n_txt}"]'
            #? Networkx graph
            self.Gx.add_node(node_idx)
            self.Gx_nodes[node_idx] = node
            self.Gx_nodes[node_idx]['color'] = n_fillcolor
            self.Gx_nodes[node_idx]['shape'] = n_shape

            return node

        # if 'handle' in n_type:
        #     print(f'      [-] existed. n_type = {n_type} | node_identifier_str = {node_identifier_str}')
        #     print(f'      [-] self.map_nodestr_nodetype[node_identifier_str] = {self.map_nodestr_nodetype[node_identifier_str]}')
        #     print(f'      [-] self.map_nodestr_node_by_type[n_type] = {self.map_nodestr_node_by_type[n_type]}')
        #     # print('>>> self.map_nodestr_nodetype', self.map_nodestr_nodetype)
        #     # print('>>> self.map_nodestr_node_by_type', self.map_nodestr_node_by_type)
        
        return self.map_nodestr_node_by_type[n_type][node_identifier_str]


    def remove_node(self, node):
        """
        Remove a node from graph.
        Can only remove node with no connection
        """
        n_name, node_identifier_str = self.get_node_name(node)
        node_idx = node['id']
        log(f'[remove_node] node_idx = {node_idx}')

        #* DEBUG
        # log(f'self.g_codes[-3] = {self.g_codes[-3]}')
        # log(f'self.g_codes[-2] = {self.g_codes[-2]}')
        # log(f'self.g_codes[-1] = {self.g_codes[-1]}')
        # log(f'self.g_nodes[-1] = {self.g_nodes[-1]}')
        # log(f'self.g_edges[-1] = {self.g_edges[-1]}')

        self.Gx.remove_node(node_idx)
        # del self.g_codes[-1]
        del self.map_nodestr_nodetype[node_identifier_str]
        del self.map_nodestr_node_by_type[node['type']][node_identifier_str]
        del self.g_codes['nodes'][node_idx]
        del self.Gx_nodes[node_idx]


    def insert_edge(self, source_node, dest_node, api_args=None, buffer_size=None,e_type=None) -> None:
        """
        Insert edge from source_node to dest_node, with specific type.

        Arguments:
            - source_node: a dict of node attribute
            - dest_node: a dict of node attribute
            - api_args: arguments fields of api calls
            - buffer_size: buffer_size field from api call
            - e_type: edge type. 
                If not defined (None), use default value = source['type] - dest['type].
                If not None (eg. with api-nproc type)

        --------------------------------------
        
        Check if source_node and dest_node exists in G.
        Check if edge(s, d) exists in G. 
            If yes, skip
            If not, insert
        """

        s_node_idx = source_node['id']
        d_node_idx = dest_node['id']

        #? do not allow self loop
        if s_node_idx == d_node_idx:
            log(f'[-] Do not allow self loop  {source_node}')
            return

        #? remove some arguments
        flags = None
        args = None
        if api_args is not None:
            args = {**api_args}
            for key in list(api_args.keys()):
                if key in ['process_identifier', 'handle', 'process_handle', 'key_handle', 'file_handle', 'source_handle', 'base_handle', 'module_address', 'base_address', 'function_address', 'module', 'module_name', 'function_name', 'basename', 'library']:
                    del args[key]
            flags = args['flags'] if 'flags' in args and not isinstance(args['flags'], int) else None


        if e_type is None:
            e_type = source_node['type']+'-'+dest_node['type']

        if source_node['type'] not in self.n_types or dest_node['type'] not in self.n_types:
            log('[-] source_node type or dest_node type out of concern: {}, {}'.format(source_node['type'], dest_node['type']))
            return
        
        if self.do_limit_edge is True and e_type not in self.limit_etypes:
            log('[-] edge type out of concern: {e_type}')
            return
        
        """ insert edge """
        edge_identifier_str = f'{s_node_idx}--{d_node_idx}'
        if edge_identifier_str not in self.map_edgestr_edgetype.keys():
            edge_idx = len(self.map_edgestr_edgetype)
            edge = {
                'type': e_type,
                'id': edge_idx,
                # 'args': flags if flags is not None and len(flags) > 0 else {},
                'args': args if args is not None and len(args) > 0 else {},
                'from': s_node_idx,
                'to': d_node_idx,
                'buffer_size': buffer_size if buffer_size is not None else -1,
                'graph': self.current_graph,
                'graph_label': self.current_graph_label
            }
            self.map_edgestr_edgetype[edge_identifier_str] = e_type
            self.map_edgestr_edge_by_type[e_type][edge_identifier_str] = edge
            # self.add_edge_args_embedding_data(args)
            
            #? to count relations to a node
            if s_node_idx not in self.map_nodeid_nrels:
                self.map_nodeid_nrels[s_node_idx] = 0
            else:
                self.map_nodeid_nrels[s_node_idx] += 1
            if d_node_idx not in self.map_nodeid_nrels:
                self.map_nodeid_nrels[d_node_idx] = 0
            else:
                self.map_nodeid_nrels[d_node_idx] += 1

            """ For visualization """
            #? Networkx graph
            self.Gx.add_edge(s_node_idx, d_node_idx)
            #? Graphviz graph
            # self.g_codes.append(f'{s_node_idx} -> {d_node_idx} [color="{e_color}" label="{source_node_identifier_str}->{dest_node_identifier_str}"]')
            self.g_codes['edges'][edge_identifier_str] = f'{s_node_idx} -> {d_node_idx} [color="{self.map_etype2style[e_type]}"]'

        return

    def encode_report(self, behavior, report_name, label, log_dir, report_cut_out_dir, nx_png_out_dir, dot_out_dir, render_svg) -> bool:
        """
        Process the data extracted from the report and save to data.json.

        Arguments:
            - behavior: extracted from cuckoo .json report, 'behavior' tag
            - report_name: graph name (graph id)
            - label: graph label (eg: benign, malware)
            - log_dir: output directory to store log
            - report_cut_out_dir: output directory to save processed report file (retain only necessary parts)
            - nx_png_out_dir: output directory for networkx graph. If value is None, do not save
            - dot_out_dir: output directory for dot template. If value is None, do not save
            - render_svg: render svg for visualization or not

        --------------------------------------

        For each process:
            - Insert it as a node (`process` type) if it calls to APIs we interest (ie. it will have some kind of connections)
            - Loop through APIs it calls, process only those we interest
                - 

        """

        log(f'\n---------------\n[encode_report] {label}')
        #* DEBUG
        # if report_name != '8f5135eec4dcb808423209163bbd94025ec47f4cb1b20dcf75b1fd56773ac58f.json':
        #     return False

        self.current_graph = label+'__'+report_name
        self.current_graph_label = label


        """ Get all the procs (process) """
        procs = behavior['processes']
        log(f'\n n_procs = {len(procs)}')
        #? loop through all procs
        for proc in procs:

            """ Get all the API calls which are called by this proc """
            api_calls = proc['calls']

            # id \t proc_name \t proc_path_severity \t regkey_written_severity \t dll_loaded_severity \t connects_host_severity
            # proc_name = proc['process_name']
            proc_name = proc['process_path']
            proc_pid = proc['pid']
            proc_ppid = proc['ppid']
            # proc_info = '{}|{}'.format(self.current_graph, proc_name)


            """ 
            A process should be a node too. But only if this process has some kind connections
            """
            valid_apis = [0 if self.do_limit_cat is True and api['category'] not in self.limit_cats else 1 for api in api_calls]
            n_valid_api = sum(valid_apis)
            # c = 0 if self.do_limit_cat is True and api_cat not in self.limit_cats else 1
            if n_valid_api == 0:
                log(f'[-] Proc {proc_pid} has no connection. Skip')
                continue

            #? insert this proc as a node
            node_proc_attr = {
                'name': str(proc['pid']), #proc['process_name'],
                'type': 'proc',
                'proc_name': proc['process_name'],
                'pid': proc['pid']
            }
            node_proc_attr = self.insert_node(node_proc_attr)
            self.map_procpath_pid[proc['process_path'].lower()] = proc['pid']

            #! Debug
            log(f'\n[ ] Proc  {proc_name} | pid {proc_pid} | ppid {proc_ppid}')
            log(f'    n_api_calls = {len(api_calls)}   |   n_valid_api: {n_valid_api}')


            """ 
            Now loop through all the api calls 
            """
            last_api_call_stringify = '' #? store string format of the api_call, so that at each loop, compare the api_call with the previous one to see if they are duplicates
            
            # last_node_api_attr = None
            api_count = 0 #? keep count of api_call
            for api_call in api_calls:
                api_count += 1
                api_name_orig = api_call['api']
                api_cat = api_call['category']
                api_args = api_call['arguments']
                api_time = api_call['time']

                #? remove the time key of this api_call object first before comparing
                del api_call['time']
                api_call_stringify = json.dumps(api_call)

                # log(f'\n[ ] API {api_name_orig}  |  api_args = {api_args}')

                """ 
                First check if only limited cats are considered 
                """
                if self.do_limit_cat is True and api_cat not in self.limit_cats:
                    # log(f'[-] Out of limit_cats ({api_cat}). Skip.')
                    continue
                

                """
                If they are duplicates, skip processing this api again 
                """
                if api_call_stringify == last_api_call_stringify:
                    # log(f'[-] Duplicate api. Skip.')
                    continue

                """
                Also skip all api that returns error.
                Detect API returning error by `last_error` field, if this field exists and value of this field > 0 => error. Skip processing this api.
                If we notice more, all these API that return error will have [...]_handle value = 0x00000000
                """
                if 'last_error' in api_call and api_call['last_error'] > 0:
                    log(f'[-] API returning error. Skip.')
                    continue

                last_api_call_stringify = api_call_stringify #? set last_api_call_stringify
                


                log(f'\n[ ] API {api_name_orig}  |  api_args = {api_args}')


                """ The `api_name` might be modified to contain extra information of the API, so let's set another variable """
                # api_name = f'{api_cat}__{api_name_orig}'
                api_name = copy.deepcopy(api_name_orig)

                #* DEBUG
                # func_name = api_args['function_name'] if 'function_name' in api_args else ''
                # log(f'\t api_name: {api_name} | function_name: {func_name} | last_api_name: {last_api_name}')


                """
                If `api_name` is `LdrGetProcedureAddress`, it's actually getting the address of the function name and call that function.
                Similar with all other Ldr[...] (eg. `LdrLoadDll`)
                """
                if api_name_orig == 'LdrGetProcedureAddress':
                    api_name = api_name+'__'+api_args['module']+'__'+api_args['function_name']
                elif api_name_orig == 'LdrLoadDll':
                    api_name = api_name+'__'+api_args['basename']
                elif api_name_orig == 'LdrGetDllHandle':
                    # log(f'\t api_args: {api_args}')
                    api_name = api_name+'__'+api_args['module_name']
                elif api_name_orig == 'LdrUnloadDll':
                    # log(f'\t api_args: {api_args}')
                    api_name = api_name+'__'+api_args['library']



                """ 
                ---------------------------------------------
                First thing first, insert api as a node
                ------
                Construct node data for this api 
                Insert this api as a node to the graph
                ---------------------------------------------
                """
                node_api_attr = {
                    'name': api_name,
                    'type': 'api',
                    'orig_name': api_name_orig,
                    'api_type': api_cat,
                    #? more arguments
                    # 'arguments': api_args
                    # 'flags': api_args['flags'] if 'flags' in api_args else '' #! flags should be inserted as edge arguments
                }
                node_api_attr = self.insert_node(node_api_attr)
                # last_api_name = api_name

                #? If there's error when inserting node, skip all the rest process
                if node_api_attr is None:
                    log(f'[-] node_api_attr = None. Skip.')
                    continue



                """
                ---------------------------------------------
                With all `Ldr[...]` api, it's necessary to consider the module being called as well.
                ------
                Construct node data for the module (real function that is called)
                Insert this module as a node to the graph
                Insert the edge between this api and this module
                """
                has_module = False
                if api_name_orig in ['LdrLoadDll', 'LdrGetDllHandle', 'LdrGetProcedureAddress', 'LdrUnloadDll']:
                    has_module = self.processModuleArgs(api_name_orig, node_api_attr, api_args)



                """
                ---------------------------------------------
                Check for `process_identifier`, if it's different from pid, very likely that this api is spawning to other process 
                (the proc with pid = process_identifier) 
                ------
                Construct node data for the `process_identifier` that the api spawns
                Insert this proc as a node to the graph
                Insert the edge from this api to this proc
                ---------------------------------------------
                """
                has_proc = False
                if 'process_identifier' in api_args:
                    has_proc = self.processProcArgs(api_args, node_api_attr, proc, node_proc_attr)


                """
                ---------------------------------------------
                If this api interacts with a registry key or a process handle, get the handle and create a node of this handle.
                ------
                Construct node data for the handle that the api interacts with
                Insert this handle as a node to the graph
                Insert the edge between this api and this handle
                ---------------------------------------------
                """
                has_handle = self.processHandleArgs(api_args, node_api_attr)



                """
                Funny thing. 
                We only concern apis that has some interactions with some entities (handle, process, module,...)
                Meaning, if one api only connects with other apis, delete it from the graph.
                --
                If this node remains in the graph, draw the edge prom previous api to this one, and set the last_node value so in the next process we use this value to check
                """
                #* DEBUG
                log(f'    node         : {node_api_attr}')
                log(f'      has_module : {has_module}')
                log(f'      has_handle : {has_handle}')
                log(f'      has_proc   : {has_proc}')
                if (node_api_attr['id'] not in self.map_nodeid_nrels) and ((has_module or has_handle or has_proc) is False):
                    log('[!] api has no connection to any module/handle/proc. Remove this api node')
                    self.remove_node(node_api_attr)
                else:
                    """ Draw an edge from proc node to this api """
                    # log(f'    Draw edge from `node_proc_attr` -> `node_api_attr`   |   {node_proc_attr}   ->   {node_api_attr}')
                    self.insert_edge(node_proc_attr, node_api_attr)

                    # last_node_api_attr = node_api_attr
                    self.apis.append(api_call)



        """ If no node in graph, stop the function. No need to save empty fig """
        total_nodes = sum([len(self.map_nodestr_node_by_type[nt]) for nt in self.n_types])
        if total_nodes == 0:
            return False

        if report_cut_out_dir is not None:
            json.dump(self.apis, open(os.path.join(report_cut_out_dir, report_name), 'w'))

        self.stats(report_name)
        self.visualize_networkx(report_name, nx_png_out_dir)
        self.visualize_graphviz(report_name, dot_out_dir, render_svg)

        return True


    def stats(self, report_name) -> None:
        """ 
        Print statistics 
        """
        log(f'\n--------\n[ ] Stat {report_name}')
        # log('self.map_nodestr_node_by_type : {self.map_nodestr_node_by_type}')
        # log('Gx_nodes : {self.Gx_nodes}')
        # log('Total process : {}'.format(len(self.map_nodestr_node_by_type['proc'])))
        # log('      API     : {}'.format(len(self.map_nodestr_node_by_type['api'])))
        # log('      handle  : {}'.format(len(self.map_nodestr_node_by_type['handle'])))
        # log('      module  : {}'.format(len(self.map_nodestr_node_by_type['module'])))
        # for n_type in ['handle', 'module']:
        for n_type in self.n_types:
            log('    Total {} \t: {}'.format(n_type, len(self.map_nodestr_node_by_type[n_type])))
            
        """ Check if any node has no connection to it """
        node_no_edge_idxs = [node for node in self.Gx if self.Gx.degree(node) == 0]
        # list_of_dangl = [node for node in G.nodes if G.out_degree(node) == 0]
        node_no_edge_types = {}
        for n_type in self.n_types:
            for node_identifier_str, node in self.map_nodestr_node_by_type[n_type].items():
                if node['id'] in node_no_edge_idxs:
                    node_no_edge_types[node['id']] = '{}__{}'.format(node['id'], n_type)
                    break
        log(f'    > node_no_edge_idxs  : {node_no_edge_idxs}')
        log(f'    > node_no_edge_types : {node_no_edge_types}')

        return
    

    def visualize_graphviz(self, report_name, dot_out_dir, render_svg) -> None:
        """ 
        Visualize graphviz
        """
        log(f'\n--------\n[ ] Output graphviz to {dot_out_dir}')
        if dot_out_dir is not None:
            # self.g_codes.append('}') #? end the dot template
            dot_temp = 'digraph G{'
            dot_temp += '\n'.join(list(self.g_codes['nodes'].values()))
            dot_temp += '\n'.join(list(self.g_codes['edges'].values()))
            dot_temp += '\n}'
            # log(f'\t dot_temp: {dot_temp}')

            # """ Save the dot template and svg visualization for the graph of this file """
            # s = Source(dot_temp, filename=os.path.join(dot_out_dir, f'{report_name}.gv'), format='svg') #? save the graph
            # s.view()

            """ Save the dot template for the graph of this file """
            dot_file = os.path.join(dot_out_dir, f'{report_name}.dot')
            s = Source(dot_temp, filename=dot_file) 
            s.save(skip_existing=None)
            # s.render()
            print('s', s)
            log(f'[+] Saved dot_temp to dot file {dot_file}')

            if render_svg:
                """ Automatically generate output file names based on the input file name and the various output formats specified by the -T flags.
                    $ dot -Tsvg -O ~/family.dot ~/debug.dot
                    Generates ~/family.dot.svg and ~/debug.dot.svg files. """
                os.system(f'dot -Tsvg -O {dot_file}')
                log(f'[+] Converted dot file {dot_file} to svg')
        

    def visualize_networkx(self, report_name, nx_png_out_dir) -> None:
        """ 
        Draw networkx
        """
        log(f'\n--------\n[ ] Output networkx to {nx_png_out_dir}')
        if nx_png_out_dir is not None:
            plt.figure(self.current_graph, figsize=(20,20))
            # plt.text(65, 60, 'Parabola', fontsize=22)
            # plt.subplots_adjust(left=0.1, right=0.2, top=0.2, bottom=0.1)

            pos = nx.spring_layout(self.Gx)
            
            #? short version of building nodes_color array
            nodes_color = [self.map_ntype2style[self.Gx_nodes[node_idx]['type']]['fillcolor'] for node_idx in self.Gx.nodes()]

            nx.draw_networkx_nodes(self.Gx, pos, 
                                    cmap=plt.get_cmap('jet'),
                                    node_color=nodes_color, 
                                    node_size=200)
            for n_type in self.n_types:
                if len(self.map_nodestr_node_by_type[n_type]) == 0:
                    continue
                nodes_lbls = {node['id']: node['id'] for node in self.map_nodestr_node_by_type[n_type].values()}
                nx.draw_networkx_labels(self.Gx, pos, 
                                        labels=nodes_lbls,
                                        font_size=6,
                                        font_color=self.map_ntype2style[n_type]['fontcolor'])

            for e_type in self.map_edgestr_edge_by_type:
                if len(self.map_edgestr_edge_by_type[e_type]) == 0:
                    continue
                edges_list = [(edge['from'], edge['to']) for edge in self.map_edgestr_edge_by_type[e_type].values()]
                nx.draw_networkx_edges(self.Gx, pos, 
                                        edgelist=edges_list, 
                                        edge_color=self.map_etype2style[e_type], 
                                        arrows=True)

            plt.tight_layout()
            nx_file = os.path.join(nx_png_out_dir, f'{report_name}.svg')
            plt.savefig(nx_file)
            plt.clf()
            # plt.show()

        return True
    


    def processModuleArgs(self, api_name_orig, node_api_attr, api_args):
        """
        ---------------------------------------------
        With all Ldr[...] api, it's necessary to consider the module being called as well.
        ------
        Construct node data for the module (real function that is called)
        Insert this module as a node to the graph
        Insert the edge between this api and this module
        ---
        One thing to note here.
        Sometimes these function calls to a process itself.
        eg. 
            {
                "category": "system", 
                "status": 1, 
                "stacktrace": [], 
                "api": "LdrGetDllHandle", 
                "return_value": 0, 
                "arguments": {
                    "module_name": "C:\\Users\\cuckoo\\AppData\\Local\\Temp\\97bc78f67e2e15028509a12618eb31561c56e1f65ef446eeae513dd7bb8b4210.exe", 
                    "stack_pivoted": 0, 
                    "module_address": "0x005e0000"
                }, 
                "time": 1599445198.97186, 
                "tid": 3904, 
                "flags": {}
            }
        In this case, do not create a new `module` node, use the `proc` node, and define e_type manually as `api-module`
        ---------------------------------------------
        """
        # has_module = True

        #? get the module name
        module_name = ''
        
        if api_name_orig == 'LdrLoadDll':
            module_name = api_args['basename'].lower()
        elif api_name_orig == 'LdrGetDllHandle':
            module_name = api_args['module_name'].lower()
        elif api_name_orig == 'LdrGetProcedureAddress':
            module_name = api_args['module'].lower()
        elif api_name_orig == 'LdrUnloadDll':
            module_name = api_args['library'].lower()
        else:
            log(f'[-] `api_name_orig` = {api_name_orig} out of [LdrLoadDll, LdrGetDllHandle, LdrGetProcedureAddress, LdrUnloadDll]')
            return False
        

        #? we only consider some modules. With other unimportant ones, just skip the rest process
        if module_name in ['uxtheme', 'xmllite']:
            log(f'[-] Unimportant module {module_name}. Skip')
            return False


        """ Check if this module is a process """
        if module_name in self.map_procpath_pid:
            #? use the node_idx of this proc, by calling `insert_node()` with name and type of this proc node (name=pid, type='proc'), the function will return the idx of this proc node
            node_module_attr = {
                'name': self.map_procpath_pid[module_name],
                'type': 'proc'
            }
            node_module_attr = self.insert_node(node_module_attr)
            if node_module_attr is not None:
                self.insert_edge(node_api_attr, node_module_attr, api_args=api_args)
        

        """ Otherwise, Handle the module
            Add this module as a node
            Draw a link from the api `Ldr...` to this module """
        if api_name_orig == 'LdrLoadDll':
            """ This api gets address of a dll. Draw a connection from api -> dll module """
            node_module_attr = {
                # 'name': map_module_adr2name[api_args['module_address']],
                'name': module_name,
                'type': 'module',
                #? more arguments
                'module_address': api_args['module_address'],
                # 'basename': api_args['basename'],
                # 'module_name': api_args['module_name'],
                # 'flags': api_args['flags'] #! flags should be edge arguments
            }
            node_module_attr = self.insert_node(node_module_attr)
            if node_module_attr is None:
                return False
            self.insert_edge(node_api_attr, node_module_attr, api_args=api_args)
            return True

        elif api_name_orig == 'LdrGetDllHandle':
            """ This api gets address of a dll. Draw a connection from api -> dll module """
            node_module_attr = {
                'name': module_name,
                'type': 'module',
                #? more arguments
                'module_address': api_args['module_address'],
            }
            node_module_attr = self.insert_node(node_module_attr)
            if node_module_attr is None:
                return False
            self.insert_edge(node_api_attr, node_module_attr, api_args=api_args)
            return True

        elif api_name_orig == 'LdrGetProcedureAddress':
            """ This api gets address of a function in the loaded dll. Draw a connection from dll module -> api """
            node_module_attr = {
                # 'name': map_module_adr2name[api_args['module_address']],
                'name': module_name,
                'type': 'module',
                #? more arguments
                'module_address': api_args['module_address'],
                'function_address': api_args['function_address'],
                'function_name': api_args['function_name'],
            }
            node_module_attr = self.insert_node(node_module_attr)
            if node_module_attr is None:
                return False
            self.insert_edge(node_module_attr, node_api_attr, api_args=api_args)
            return True
        
        elif api_name_orig == 'LdrUnloadDll':
            """ This api unload a loaded dll. Draw a connection from dll module -> api """
            node_module_attr = {
                'name': module_name,
                'type': 'module',
                #? more arguments
                'module_address': api_args['module_address'],
            }
            node_module_attr = self.insert_node(node_module_attr)
            if node_module_attr is None:
                return False
            self.insert_edge(node_api_attr, node_module_attr, api_args=api_args)
            return True

        return False


    def check_addr_empty(self, handle_addr) -> bool:
        if handle_addr[:2] == '0x':
            n_handle_adr = handle_addr[2:]
            la = len(n_handle_adr)
            if n_handle_adr == '0'*la or n_handle_adr == 'f'*la:
                return True
        return False


    def processHandleArgs(self, api_args, node_api_attr):
        """
        ---------------------------------------------
        If this api interacts with a registry key or a process handle, get the handle and create a node of this handle.
        ------
        Construct node data for the handle that the api interacts with
        Insert this handle as a node to the graph
        Insert the edge between this api and this handle
        ---------------------------------------------
        """
        has_handle = False

        """ This is special case.
            When NtClose calls to a handle, check if that handle exists first.
            If this handle never appears before, why close? Just ignore it. """
        if 'NtClose' in node_api_attr['name']:
            if 'handle' in api_args:
                exists = False
                handle_addr = api_args['handle']
                #? check if this handle exists in the graph
                if handle_addr not in self.map_addr_path:
                    #? if not
                    log(f'[!] NtClose close an unknown handle  {handle_addr}')
                    return False
            else:
                log(f'[!] !!!!! NtClose without handle.  node_api_attr = {node_api_attr}  |  api_args = {api_args}')
            return False

        """ loop through all arguments """
        for arg_key in api_args:
            #? we care only about key_handle, file_handle
            # if arg_key == 'handle' or '_handle' in arg_key:
            # if (arg_key == 'handle' or '_handle' in arg_key) and arg_key != 'process_handle':
            if arg_key in ['key_handle', 'file_handle']:
                handle_addr = api_args[arg_key]
                if self.check_addr_empty(handle_addr):
                    if 'base_handle' in api_args:
                        handle_addr = api_args['base_handle']
                # print(f'\n (*) arg_key = {arg_key}  |  handle_addr = {handle_addr}  |  api_args = {api_args}')

                path = ''
                if arg_key == 'file_handle': #? process file handle
                    #? overwrite
                    if 'filepath' in api_args:
                        self.map_addr_path[handle_addr] = api_args['filepath']
                    elif 'dirpath' in api_args:
                        self.map_addr_path[handle_addr] = api_args['dirpath']
                    else:
                        self.map_addr_path[handle_addr] = handle_addr
                    path = self.map_addr_path[handle_addr]

                elif arg_key == 'key_handle': #? process key handle
                    #? overwrite
                    if 'regkey' in api_args:
                        self.map_addr_path[handle_addr] = api_args['regkey']
                    elif 'path' in api_args:
                        self.map_addr_path[handle_addr] = api_args['path']
                    else:
                        self.map_addr_path[handle_addr] = handle_addr
                    path = self.map_addr_path[handle_addr]
                
                #? insert handle node
                node_handle_attr = None
                node_handle_attr_tmp = {
                    # 'name': api_args[arg_key], #! for handle types, node name is handle address
                    'name': path,
                    # 'type': 'handle',
                    # 'ctype': arg_key,
                    'type': arg_key,
                    'address': api_args[arg_key], #! send an address field
                    # 'path': path,
                }
                node_handle_attr = self.insert_node(node_handle_attr_tmp)
                # print('*** inserting ', node_handle_attr_tmp)
                # print('    node_handle_attr', node_handle_attr)
                if node_handle_attr is None:
                    continue

                has_handle = True

                # #? now, some connections will start FROM the handle TO the api
                # if arg_key in ['base_handle', 'source_handle']:
                #     self.insert_edge(node_handle_attr, node_api_attr, api_args=api_args)
                # else: #? else, it will start FROM the api TO the handle
                #     self.insert_edge(node_api_attr, node_handle_attr, api_args=api_args)

                api_name = node_api_attr['name'].lower()
                if 'open' in api_name or 'set' in api_name or 'write' in api_name or 'create' in api_name: #? api -> handle
                    self.insert_edge(node_api_attr, node_handle_attr, api_args=api_args)
                else: #? handle -> api
                    self.insert_edge(node_handle_attr, node_api_attr, api_args=api_args)


        return has_handle


    
    def processProcArgs(self, api_args, node_api_attr, proc, node_proc_attr):
        """ 
        ---------------------------------------------
        Check for `process_identifier`, if it's different from pid, very likely that this api is spawning to other process 
        (the proc with pid = process_identifier) 
        ------
        Construct node data for the `process_identifier` that the api spawns
        Insert this proc as a node to the graph
        Insert the edge from this api to this proc
        ---------------------------------------------
        """
        #? check if this api is spawning another process
        if api_args['process_identifier'] != proc['pid']:
            #? insert this node_proc first
            node_nproc_attr = {
                'name': str(api_args['process_identifier']),
                'type': 'proc',
                'pid': api_args['process_identifier']
            }
            node_nproc_attr = self.insert_node(node_nproc_attr)
            log(f'    [processProcArgs] node_nproc_attr = {node_nproc_attr}')
            self.insert_edge(node_api_attr, node_nproc_attr, api_args=api_args)
        else:
            self.insert_edge(node_api_attr, node_proc_attr, api_args=api_args)

        return True
    

