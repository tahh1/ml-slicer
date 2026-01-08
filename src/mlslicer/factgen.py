import ast
import json
import logging
from collections import defaultdict
from mlslicer.scope import ScopeManager

logger = logging.getLogger(__name__)

class FactManager(object):

    def __init__(self) -> None:
        self.invo_num = 0 
        self.var_num = 0
        self.func_num = 0
        self.heap_num = 0
        self.datalog_facts = {
            "InvokeInjected":[],
            "LoadSliceMultiDim":[],
            "StoreSliceMultiDim":[],
            "For":[],
            "While":[],
            "If":[],
            "OrElse":[],
            "MethodReturn":[],
            "With":[],
            "AssignVar": [],
            "AssignGlobal": [],
            "AssignStrConstant": [],
            "AssignBoolConstant": [],
            "AssignBool": [],
            "AssignIntConstant": [],
            "AssignFloatConstant": [],
            "AssignBinOp": [],
            "AssignUnaryOp": [],
            "LoadField": [],
            "StoreField": [],
            "StoreFieldSSA": [],
            "LoadIndex": [],
            "StoreIndex": [],
            "StoreIndexSSA": [],
            "LoadSlice": [],
            "StoreSlice": [],
            "StoreSliceSSA": [],
            "ModuleAliases":[],
            "Invoke": [],
            "CallGraphEdge": [],
            "ActualParam": [],
            "ActualKeyParam": [], 
            "FormalParam": [],
            "ActualReturn": [],
            "FormalReturn": [],
            # "MethodUpdate": [],
            "VarType": [],
            "SubType": [],
            "VarInMethod": [],
            "Alloc": [],
            "LocalMethod": [],
            "LocalClass": [],
            "InvokeInLoop": [],
            "NextInvoke": [],
            "InvokeLineno": []
        }


    def add_fact(self, fact_name, fact_tuple):
        # print(fact_name, fact_tuple)
        fact_tuple = (str(t) for t in fact_tuple)
        self.datalog_facts[fact_name].append(fact_tuple)

    def get_new_invo(self):
        old_invo = self.invo_num
        self.invo_num += 1
        return "$invo" + str(old_invo)

    def get_new_var(self):
        old_var = self.var_num
        self.var_num += 1
        return "_var" + str(old_var)
    
    def get_new_func(self):
        old_func = self.func_num
        self.func_num += 1
        return "_func" + str(old_func)

    def get_new_heap(self):
        old_heap = self.heap_num
        self.heap_num += 1
        return "$heap" + str(old_heap)

    def get_new_list(self):
        old_var = self.var_num
        self.var_num += 1
        return "$list" + str(old_var)

    def get_new_tuple(self):
        old_var = self.var_num
        self.var_num += 1
        return "$tuple" + str(old_var)

    def get_new_set(self):
        old_var = self.var_num
        self.var_num += 1
        return "$set" + str(old_var)

    def get_new_dict(self):
        old_var = self.var_num
        self.var_num += 1
        return "$dict" + str(old_var)

    def get_new_for(self):
        old_var = self.var_num
        self.var_num += 1
        return "$for" + str(old_var)
    
    def get_new_if(self):
        old_var = self.var_num
        self.var_num += 1
        return "$if" + str(old_var)
    
    def get_new_else(self):
        old_var = self.var_num
        self.var_num += 1
        return "$else" + str(old_var)
    
    def get_new_while(self):
        old_var = self.var_num
        self.var_num += 1
        return "$while" + str(old_var)



class FactGenerator(ast.NodeVisitor):
    def __init__(self, json_path) -> None:
        super().__init__()
        self.FManager = FactManager()
        self.scopeManager = ScopeManager()
        self.load_type_map(json_path)
        self.meth_map = {
            ast.Set: self.FManager.get_new_set,
            ast.Tuple: self.FManager.get_new_tuple,
            ast.List: self.FManager.get_new_list,
            ast.Dict: self.FManager.get_new_dict,
            ast.SetComp: self.FManager.get_new_set,
            ast.GeneratorExp: self.FManager.get_new_var,
            ast.ListComp: self.FManager.get_new_list,
            ast.DictComp: self.FManager.get_new_dict,
            ast.If: self.FManager.get_new_if,
            "else": self.FManager.get_new_else,
            ast.While: self.FManager.get_new_while,
            ast.For: self.FManager.get_new_for,
        }
        self.import_map = {}
        self.imports=[]
        self.import_aliases={}
        self.meth2invokes = defaultdict(list)
        self.meth_in_loop = set()
        self.in_loop = False
        self.loop_vars = []
        self.in_class = False
        self.injected_methods = ["__phi__", "set_field_wrapper", "set_index_wrapper", "global_wrapper"]
    
    def load_type_map(self, json_path):
        with open(json_path) as f:
            self.type_map = json.load(f) 
        # Builtin Types
        self.type_map.update({'set':['module', 'set'],
                            'list':['module', 'list'],
                            'dict':['module', 'dict'],
                            'str':['module', 'str']})
        def filter_unbound(x):
            return ' | '.join([t for t in x.split(' | ') if t != "Unbound"])
        
        for varname, v in self.type_map.items():
            if v[0] == "var":
                self.FManager.add_fact("VarType", (varname, filter_unbound(v[1])))
        

    def import_map_get(self, key):
        if key in self.import_map:
            return self.import_map[key]
        return key

    def get_cur_sig(self):
        return self.scopeManager.get_cur_sig()
    
    def mark_localvars(self, varname, lineno):
        if self.scopeManager.in_globals(varname):
            self.FManager.add_fact("AssignGlobal", (varname, varname,lineno))
            return
        self.FManager.add_fact("VarInMethod", (varname, self.get_cur_sig()))

    def mark_loopcalls(self):
        for meth_name, loop_var in self.meth_in_loop:
            for invo in self.meth2invokes[meth_name]:
                self.FManager.add_fact("InvokeInLoop", (invo, loop_var))

    def build_invoke_graphs(self):
        for _, invos in self.meth2invokes.items():
            for (from_invo, to_invo) in zip(invos, invos[1:] + ["invo_end"]):
                self.FManager.add_fact("NextInvoke", (from_invo, to_invo))

    def add_loop_facts(self, cur_invo, meth_name):
        for loop_var in self.loop_vars:
            self.FManager.add_fact("InvokeInLoop", (cur_invo, loop_var))
            self.meth_in_loop.add((meth_name, loop_var))

    def visit_Body(self, body):
        if isinstance(body, list):
            new_values = []
            for value in body:
                if isinstance(value, ast.AST):
                    value = self.visit(value)
                    if value is None:
                        continue
                    elif not isinstance(value, ast.AST):
                        new_values.extend(value)
                        continue
                new_values.append(value)
            body[:] = new_values
        return body

    def visit_Module(self, node) :
        ret = ast.NodeTransformer.generic_visit(self, node)
        #print(ret)
        self.mark_loopcalls()
        self.build_invoke_graphs()
        return ret

    def visit_Import(self,node):
    	for name in node.names:
            #print(ast.dump(node))
            assert type(name) == ast.alias
            #print(name.name)
            if(name.asname!=None):
                self.FManager.add_fact("ModuleAliases", (name.name,name.asname,))
                self.import_aliases[name.asname]=name.name  
            else: 
                self.imports.append(name.name)  
            return ast.NodeTransformer.generic_visit(self, node)

    def visit_ImportFrom(self,node):
        for name in node.names:
            assert type(name) == ast.alias
            self.import_map[name.name] = '.'.join([node.module, name.name])
            #print(node.module,name.name)
        return ast.NodeTransformer.generic_visit(self, node)

    def visit_Global(self, node):
        self.scopeManager.update_globals(node.names)
        return node

    def visit_Nonlocal(self, node):
        self.scopeManager.update_globals(node.names)
        return node

    def visit_ClassDef(self, node):
        self.scopeManager.enterNamedBlock(node.name)
        self.in_class = True
        self.FManager.add_fact("LocalClass", (node.name,node.lineno,node.end_lineno))
        for base in node.bases:
            base_type = self.type_map[base.id][1]
            if base_type.startswith("Type["):
                base_type = base_type[5:-1]
            self.FManager.add_fact("SubType", (node.name, base_type))
        self.visit_Body(node.body)
        self.in_class = False
        self.scopeManager.leaveNamedBlock()
        return node

    def visit_With(self,node):
        #print(ast.dump(node))
        self.FManager.add_fact("With",(node.lineno,node.end_lineno))
        return ast.NodeTransformer.generic_visit(self, node)

    def visit_FunctionDef(self, node):
        self.scopeManager.enterNamedBlock(node.name)
        #print(ast.dump(node))
        if(len(node.body)>0 and isinstance(node.body[-1],ast.Return)):
            returnnode=node.body[-1]
            #print(ast.dump(node.body[-1]))
            if(isinstance(returnnode.value,ast.Name)):
	            self.FManager.add_fact("MethodReturn",(self.get_cur_sig(),returnnode.value.id,returnnode.lineno))
            elif(isinstance(returnnode.value,ast.Tuple)):
	            for el in returnnode.value.elts:
		            assert(isinstance(el,ast.Name))
		            self.FManager.add_fact("MethodReturn",(self.get_cur_sig(),el.id,returnnode.lineno))
            

        self.FManager.add_fact("LocalMethod", (self.get_cur_sig(),node.lineno,node.end_lineno,False))
        meth = self.get_cur_sig()
        for i, arg in enumerate(node.args.args):
            self.mark_localvars(arg.arg,node.lineno)
            if self.in_class:
                self.FManager.add_fact("FormalParam", (i, meth, arg.arg))
            else:
                self.FManager.add_fact("FormalParam", (i+1, meth, arg.arg))
        self.visit_Body(node.body)
        if self.in_class and node.name == "__init__" and len(node.args.args) > 0:
            self.FManager.add_fact("Alloc", (node.args.args[0].arg, self.FManager.get_new_heap(), self.get_cur_sig()))
            self.FManager.add_fact("FormalReturn", (0, meth, node.args.args[0].arg))
        self.scopeManager.leaveNamedBlock()
        return node
    
    def visit_For(self, node):
        assert(type(node.iter) == ast.Name)
        assert(type(node.target) == ast.Name)
        new_iter = self.meth_map[ast.For]()
        #print(ast.dump(node))
        #print(node.lineno,node.end_lineno)
        self.FManager.add_fact("For", (new_iter,node.lineno,node.end_lineno,node.iter.id))

        self.mark_localvars(node.target.id,node.lineno)
        self.FManager.add_fact("LoadIndex", (node.target.id, node.iter.id, "index_placeholder",node.lineno))
        self.in_loop = True
        self.loop_vars.append(node.iter.id)
        ret = ast.NodeTransformer.generic_visit(self, node)
        self.loop_vars.pop()
        self.in_loop = False
        return ret

    def visit_While(self, node):
        assert(type(node.test) == ast.Name)
        new_iter = self.meth_map[ast.While]()
        self.FManager.add_fact("While", (new_iter,node.lineno,node.end_lineno,node.test.id))
        ret = ast.NodeTransformer.generic_visit(self, node)
        return ret

        #print("In while", node.lineno,node.end_lineno)

    
    def visit_ExceptHandler(self, node):
        node.body = self.visit_Body(node.body)
        return node
    
    # async ast nodes
    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_AsyncFor(self, node):
        return self.visit_For(node)
    
    def visit_If(self,node):
        assert(type(node.test) == ast.Name)
        new_iter = self.meth_map[ast.If]()
        self.FManager.add_fact("If", (new_iter,node.lineno,node.end_lineno,node.test.id))
        if(len(node.orelse)>0):
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Else block detected: orelse_line=%s, body_end=%s",
                    node.orelse[0].lineno - 1,
                    node.body[-1].end_lineno + 1,
                )
            new_iter = f"$else{new_iter[3:]}"
            assert((node.orelse[0].lineno-1 if not isinstance(node.orelse[0],ast.If) else node.orelse[0].lineno) ==node.body[-1].end_lineno+1)
            self.FManager.add_fact("OrElse", (new_iter,node.body[-1].end_lineno+1,node.orelse[-1].end_lineno))
        #print("IFFF",ast.dump(node),node.lineno,node.end_lineno,node.body[-1].end_lineno)

        
        ret = ast.NodeTransformer.generic_visit(self, node)
        return ret
        



    def visit_Return(self, node):
        if type(node.value) == ast.Name:
            self.FManager.add_fact("FormalReturn", (0, self.get_cur_sig(), node.value.id))
        elif type(node.value) == ast.Tuple:
            for i, x in enumerate(node.value.elts):
                assert type(x) == ast.Name
                self.FManager.add_fact("FormalReturn", (i, self.get_cur_sig(), x.id))
        return ast.NodeTransformer.generic_visit(self, node)
    
    def visit_Yield(self, node):
        if type(node.value) == ast.Name:
            self.FManager.add_fact("FormalReturn", (0, self.get_cur_sig(), node.value.id))
        elif type(node.value) == ast.Tuple:
            for i, x in enumerate(node.value.elts):
                assert type(x) == ast.Name
                self.FManager.add_fact("FormalReturn", (i, self.get_cur_sig(), x.id))
        return ast.NodeTransformer.generic_visit(self, node)

    def handle_assign_value(self, target, value, lineno):
        assert(type(target) == ast.Name)
        target_name = target.id
        self.mark_localvars(target_name,lineno)
        if type(value) == ast.Name:
            self.FManager.add_fact("AssignVar", (target_name, value.id, lineno))
        elif type(value) == ast.Call:
            # handle injected method
            if type(value.func) == ast.Name and value.func.id in self.injected_methods:
                if value.func.id == "set_field_wrapper":
                    self.FManager.add_fact("StoreFieldSSA", (target_name, value.args[0].id, value.args[1].value, value.args[2].id,lineno))
                elif value.func.id == "set_index_wrapper":
                    idx = value.args[1]
                    if type(idx) == ast.Name:
                        self.FManager.add_fact("StoreIndexSSA", (target_name, value.args[0].id, idx.id, value.args[2].id,lineno))
                    elif type(idx) == ast.Index:
                        #print(ast.dump(value))
                        assert type(idx.value) == ast.Name
                        self.FManager.add_fact("StoreIndexSSA", (target_name, value.args[0].id, idx.value.id, value.args[2].id,lineno))
                    elif type(idx) == ast.Call:
                        assert type(idx.func) == ast.Name
                        idx_ids = [x.id if type(x) == ast.Name else "none" for x in idx.args]
                        self.FManager.add_fact("StoreSliceSSA", (target_name, value.args[0].id, *idx_ids, value.args[2].id,lineno))
                    elif type(idx) == ast.Tuple:
                       self.FManager.add_fact("StoreIndexSSA", (target_name, value.args[0].id, "slice_placeholder", value.args[2].id,lineno))
                       for i,el in enumerate(idx.elts):
                            if type(el)== ast.Name:
                                self.FManager.add_fact("StoreSliceMultiDim", (target_name, value.args[0].id, 0,el.id,i, lineno))
                            elif type(el) == ast.Call:
                                assert type(el.func) == ast.Name
                                idx_ids = [(i,x.id) if type(x) == ast.Name else (i,"none") for i,x in enumerate(el.args)]
                                for id in idx_ids:
                                    self.FManager.add_fact("StoreSliceMultiDim", (target_name, value.args[0].id, id[0],id[1],i, lineno))
                        
                    else:
                        assert False, "Unknown slice!"
                elif value.func.id == "global_wrapper":
                    self.FManager.add_fact("AssignGlobal", (target_name, value.args[0].id,lineno))
                elif value.func.id == "__phi__":
                    self.FManager.add_fact("AssignVar", (target_name, value.args[0].id,lineno))
                    self.FManager.add_fact("AssignVar", (target_name, value.args[1].id,lineno))
                    cur_invo = self.visit_Call(value)
                    self.FManager.add_fact("ActualReturn", (0, cur_invo, target_name))
                    self.FManager.add_fact("ActualParam", (1, cur_invo, value.args[0].id))
                    self.FManager.add_fact("ActualParam", (2, cur_invo, value.args[1].id))
                    new_heap=self.FManager.get_new_heap()
                    self.FManager.add_fact("Alloc", (target_name, new_heap, self.get_cur_sig(),lineno))
                return
                    
            cur_invo = self.visit_Call(value)
            self.FManager.add_fact("ActualReturn", (0, cur_invo, target_name))
            new_heap=self.FManager.get_new_heap()
            self.FManager.add_fact("Alloc", (target_name, new_heap, self.get_cur_sig(),lineno))
        elif type(value) == ast.Constant:
            if type(value.value) == int:
                self.FManager.add_fact("AssignIntConstant", (target_name, value.value,lineno))
            elif type(value.value) == bool:
                self.FManager.add_fact("AssignBoolConstant", (target_name, value.value,lineno))
            elif type(value.value) == float:
                self.FManager.add_fact("AssignFloatConstant", (target_name, value.value,lineno))
            elif type(value.value) == str:
                self.FManager.add_fact("AssignStrConstant", (target_name, value.value.encode("unicode_escape").decode("utf-8"),lineno))
            self.FManager.add_fact("Alloc", (target_name, self.FManager.get_new_heap(), self.get_cur_sig()))
        # other literals
        elif type(value) in [ast.List, ast.Tuple, ast.Set]:
            if len(value.elts) <= 50 and ast.Name in [type(x) for x in value.elts]:
                for i, x in enumerate(value.elts):
                    if type(x) == ast.Name:
                        self.FManager.add_fact("StoreIndex", (target_name, i, x.id,lineno))
                    else:
                        assert type(x) ==  ast.Constant
            new_iter = self.meth_map[type(value)]()
            self.FManager.add_fact("Alloc", (new_iter, self.FManager.get_new_heap(), self.get_cur_sig()))
            self.FManager.add_fact("AssignVar", (target_name, new_iter,lineno))
        elif type(value) == ast.Dict:
            if len(value.values) <= 50 and ast.Name in [type(x) for x in value.values]:
                for k, v in zip(value.keys, value.values):
                    if type(v) == ast.Name:
                        if k == None:
                            self.FManager.add_fact("AssignVar", (target_name, v.id,lineno))
                        else:
                            k_literal = k.id if type(k) == ast.Name else k.value
                            self.FManager.add_fact("StoreIndex", (target_name, k_literal, v.id,lineno))
                    else:
                        assert type(v) ==  ast.Constant
            new_iter = self.meth_map[type(value)]()
            self.FManager.add_fact("Alloc", (new_iter, self.FManager.get_new_heap(), self.get_cur_sig()))
            self.FManager.add_fact("AssignVar", (target_name, new_iter,lineno))
        # comprehensions [TODO]
        elif type(value) in [ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp]:
            new_iter = self.meth_map[type(value)]()
            self.FManager.add_fact("Alloc", (new_iter, self.FManager.get_new_heap(), self.get_cur_sig()))
            self.FManager.add_fact("AssignVar", (target_name, new_iter,lineno))
        elif type(value) == ast.Lambda:
            new_iter = self.FManager.get_new_heap()
            self.FManager.add_fact("Alloc", (new_iter, self.FManager.get_new_heap(), self.get_cur_sig()))
            self.FManager.add_fact("AssignVar", (target_name, new_iter,lineno))
        elif type(value) == ast.Subscript:
            assert type(value.value) == ast.Name
            if type(value.slice) == ast.Index:
                assert type(value.slice.value) == ast.Name
                self.FManager.add_fact("LoadIndex", (target_name, value.value.id, value.slice.value.id,lineno))
                #print(ast.dump(value))
            elif type(value.slice) == ast.Slice:
                slice_ids=[x.id if x else "none" for x in [value.slice.lower, value.slice.upper, value.slice.step]]
                self.FManager.add_fact("LoadSlice", (target_name, value.value.id, *slice_ids,lineno))
                self.FManager.add_fact("Alloc", (target_name, self.FManager.get_new_heap(), self.get_cur_sig())) # should be generated on the fly
                #print(ast.dump(value))
            elif type(value.slice) == ast.ExtSlice:
                for dimension,el in enumerate(value.slice.dims):
                     if(type(el)==ast.Slice):
                        slice_ids=[(position,x.id) if x else (position,"none") for position,x in enumerate([el.lower, el.upper, el.step])]
                        for id in slice_ids:
                            self.FManager.add_fact("LoadSliceMultiDim", (target_name, value.value.id, id[0],id[1],dimension,lineno))
                     else:
                         self.FManager.add_fact("LoadSliceMultiDim", (target_name, value.value.id, 0,el.value.id,dimension,lineno))
                             
                     #print(ast.dump(el))
                self.FManager.add_fact("LoadIndex", (target_name, value.value.id, "slice_placeholder",lineno))
                self.FManager.add_fact("Alloc", (target_name, self.FManager.get_new_heap(), self.get_cur_sig())) # should be generated on the fly
                #print(ast.dump(value))
        elif type(value) == ast.Attribute:
            assert type(value.value) == ast.Name
            self.FManager.add_fact("LoadField", (target_name, value.value.id, value.attr,lineno))
        elif type(value) == ast.BinOp:
            assert type(value.left) == ast.Name
            assert type(value.right) == ast.Name
            self.FManager.add_fact("AssignBinOp", (target_name, value.left.id, value.op.__class__.__name__, value.right.id,lineno))
            self.FManager.add_fact("Alloc", (target_name, self.FManager.get_new_heap(), self.get_cur_sig()))
        elif type(value) == ast.UnaryOp:
            assert type(value.operand) in [ast.Name, ast.Constant]
            if type(value.operand) == ast.Name:
                self.FManager.add_fact("AssignUnaryOp", (target_name, value.op.__class__.__name__, value.operand.id,lineno))
            elif type(value.operand) == ast.Constant:
                self.FManager.add_fact("AssignUnaryOp", (target_name, value.op.__class__.__name__, value.operand.value,lineno))
        elif type(value) == ast.Compare:
            assert type(value.left) == ast.Name
            self.FManager.add_fact("AssignVar", (target_name, value.left.id,lineno))
            for com in value.comparators:
                assert type(com) == ast.Name
                self.FManager.add_fact("AssignVar", (target_name, com.id,lineno)) # maybe vectors!! [TODO]
        elif type(value) == ast.BoolOp:
            for v in value.values:
                assert type(v) == ast.Name
                self.FManager.add_fact("AssignVar", (target_name, v.id,lineno))
        elif type(value) == ast.Starred:
            assert type(value.value) == ast.Name
            self.FManager.add_fact("LoadField", (target_name, value.value.id, "",lineno)) # better modeling? [TODO]
        elif type(value) == ast.IfExp:
            assert type(value.test) == ast.Name
            assert type(value.body) == ast.Name
            assert type(value.orelse) == ast.Name
            self.FManager.add_fact("AssignVar", (target_name, value.test.id,lineno))
            self.FManager.add_fact("AssignVar", (target_name, value.body.id,lineno))
            self.FManager.add_fact("AssignVar", (target_name, value.orelse.id,lineno))
        elif type(value) == ast.JoinedStr:
            self.FManager.add_fact("AssignStrConstant", (target_name, "str_placeholder",lineno))
        else:
            logger.warning("Unknown source type: %s", type(value))
            assert 0

    def visit_Assign(self, node):
        for target in node.targets:
            if type(target) == ast.Name:
                self.handle_assign_value(target, node.value, node.lineno)
            elif type(target) == ast.Starred:
                self.handle_assign_value(target.value, node.value,node.lineno)
            elif type(target) == ast.Attribute:
                assert False, "Case deprecated!"
            elif type(target) == ast.Subscript:
                assert False, "Case deprecated!"
            elif type(target) == ast.Tuple:
                assert type(node.value) == ast.Call
                cur_invo = self.visit_Call(node.value)
                for i, t in enumerate(target.elts):
                    assert type(t) == ast.Name
                    self.mark_localvars(t.id,node.lineno)
                    self.FManager.add_fact("ActualReturn", (i, cur_invo, t.id))
                    self.FManager.add_fact("Alloc", (t.id, self.FManager.get_new_heap(), self.get_cur_sig()))
            else:
                assert False, "Unkown target type! " + str(type(target))

        return node
    
    def visit_Call(self, node):
        cur_invo = self.FManager.get_new_invo()
        self.FManager.add_fact("InvokeLineno", (cur_invo, node.lineno))
        self.meth2invokes[self.get_cur_sig()].append(cur_invo)
        #print(ast.dump(node, indent=4))
        if type(node.func) == ast.Name and node.func.id in self.injected_methods:
        	self.FManager.add_fact("InvokeInjected", (cur_invo, node.func.id, self.get_cur_sig()))
        	#print(ast.dump(node, indent=4))
        	return cur_invo
        elif type(node.func) == ast.Attribute:
            hasInnerCall = self.visit_Attribute(node.func, cur_invo=cur_invo)
            # simulating invocations insde higher-order functions
            if hasInnerCall:
                new_invo = self.FManager.get_new_invo()
                self.FManager.add_fact("InvokeLineno", (new_invo, node.lineno))
                func_name = ""
                for kw in node.keywords:
                    if kw.arg == "func":
                        assert type(kw.value) == ast.Name
                        func_name = kw.value.id
                if func_name == "":
                    assert type(node.args[0]) == ast.Name
                    func_name = node.args[0].id
                self.meth2invokes[self.get_cur_sig()].append(new_invo)
                self.FManager.add_fact("Invoke", (new_invo, func_name, self.get_cur_sig()))
                if self.in_loop:
                    self.add_loop_facts(new_invo, node.argsS[0].id)
                self.FManager.add_fact("ActualParam", (1, new_invo, node.func.value.id))
                self.FManager.add_fact("ActualReturn", (0, new_invo, node.func.value.id))
        elif type(node.func) == ast.Name:
            self.FManager.add_fact("Invoke", (cur_invo, node.func.id, self.get_cur_sig()))
            if self.in_loop:
                self.add_loop_facts(cur_invo, node.func.id)
        else:
            logger.error("Impossible node.func type: %s", type(node.func))
        self.visit_arguments(node.args, cur_invo=cur_invo)
        self.visit_keywords(node.keywords, cur_invo=cur_invo)
        return cur_invo


    def visit_Attribute(self, node, assigned = False, cur_invo = None):
        assert type(node.value) == ast.Name
        #print(ast.dump(node, indent=4))
        if cur_invo:
            value_type = self.type_map[node.value.id]
            method_sig = ".".join([value_type[1].replace('Self@', ''), node.attr]) if value_type[1]!="Unknown" else ".".join([node.value.id, node.attr]) 
            if value_type[0] == "var":
                self.FManager.add_fact("ActualParam", (0, cur_invo, node.value.id))        
            self.FManager.add_fact("Invoke", (cur_invo, method_sig, self.get_cur_sig()))
            if self.in_loop:
                self.add_loop_facts(cur_invo, method_sig)
            if method_sig in ["pandas.Series.map", "pandas.Series.apply", "pandas.DataFrame.apply", "FrameOrSeries.apply",  "pandas.DataFrame.applymap"]:
                return True

    def visit_arguments(self, args, cur_invo=None):
        if type(args) == ast.arguments:
            return args
        for i, arg in enumerate(args):
            if type(arg) == ast.Starred:
                arg = arg.value
            assert type(arg) == ast.Name
            self.FManager.add_fact("ActualParam", (i + 1, cur_invo, arg.id))
        return args

    def visit_keywords(self, keywords, cur_invo):
        for keyword in keywords:
            assert type(keyword.value) == ast.Name
            self.FManager.add_fact("ActualKeyParam", (keyword.arg, cur_invo, keyword.value.id))
        return keywords

    # keep exprs below unchanged (for now)
    def visit_ListComp(self, node):
        return [], node

    def visit_SetComp(self, node):
        return [], node

    def visit_DictComp(self, node):
        return [], node

    def visit_GeneratorExp(self, node):
        return [], node

    def visit_comprehension(self, node):
        return [], node

    def visit_FormattedValue(self, node):
        return [], node

    def visit_JoinedStr(self, node):
        return [], node
