# Copyright 2016
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Extern P4 type template generator
# Jeferson Santiago da Silva (eng.jefersonsantiago@gmail.com)
#

import sys
import os.path
import re
from struct import *

CPP_STR =\
'/* Copyright 2016\n\
 *\n\
 * Licensed under the Apache License, Version 2.0 (the "License");\n\
 * you may not use this file except in compliance with the License.\n\
 * You may obtain a copy of the License at\n\
 *\n\
 *   http://www.apache.org/licenses/LICENSE-2.0\n\
 *\n\
 * Unless required by applicable law or agreed to in writing, software\n\
 * distributed under the License is distributed on an "AS IS" BASIS,\n\
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n\
 * See the License for the specific language governing permissions and\n\
 * limitations under the License.\n\
 */\n\
\n\
/* Extern P4 type C++ template\n\
 * Jeferson Santiago da Silva (eng.jefersonsantiago@gmail.com)\n\
 */\n\
\n\
#include <bm/bm_sim/extern.h>\n\
\n\
//#include <your lib goes here>\n\
\n\
using namespace std;\n\
\n\
template <typename... Args>\n\
using ActionPrimitive = bm::ActionPrimitive<Args...>;\n\
\n\
// Place here the necessary bmv2 classes, Ex:\n\
//using bm::Data;\n\
//using bm::Header;\n\
//using bm::PHV;\n\
\n\
using bm::ExternType;\n\
\n\
class %s: public ExternType {\n\
 public:\n\
%s\n\
\n\
 // Init variables/classes\n\
  void init() override {\n\
    // Put your code here\n\
    // Init the attributes and the classes\n\
  }\n\
\n\
  // Exported methods to P4\n\
%s\n\
 private:\n\
  // Declared attributes (only integer supported)\n\
%s\n\
\n\
  // Stateful parameters (user class declarations)\n\
\n\
};\n\
\n\
BM_REGISTER_EXTERN(%s);\n\
%s\n\
\n\
// Dummy function: must be defined as extern and called in the target\n\
int import_extern_%s() {\n\
  return 0;\n\
}\n'

P4_STR =\
'/* Copyright 2016\n\
 *\n\
 * Licensed under the Apache License, Version 2.0 (the "License");\n\
 * you may not use this file except in compliance with the License.\n\
 * You may obtain a copy of the License at\n\
 *\n\
 *   http://www.apache.org/licenses/LICENSE-2.0\n\
 *\n\
 * Unless required by applicable law or agreed to in writing, software\n\
 * distributed under the License is distributed on an "AS IS" BASIS,\n\
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n\
 * See the License for the specific language governing permissions and\n\
 * limitations under the License.\n\
 */\n\
\n\
/* Extern P4 type P4 template\n\
 * Jeferson Santiago da Silva (eng.jefersonsantiago@gmail.com)\n\
 */\n\
\n\
extern_type %s {\n\
%s\n\
%s\n\
}'


def dump_ext_files(file_config):
    name_pres = False
    attr_pres = False
    meth_pres = False
    cpp_dump_file = CPP_STR
    p4_dump_file = P4_STR

    file_ = open(file_config, "r")

    for line in file_:
        if re.match('extern_type =', line) and not name_pres:
            name_pres = True
            ext_name = str(re.sub('extern_type =', '', line)).strip()

        if re.match('extern_attributes =', line) and not attr_pres:
            attr_pres = True
            ext_attr = str(re.sub('extern_attributes =', '', line))
            ext_attr_ = re.split('\W+', ext_attr.strip())
            ext_attr_str= '  BM_EXTERN_ATTRIBUTES {\n'
            p4_ext_attr_str= ''
            for i in ext_attr_:
                ext_attr_str = ext_attr_str + \
                                '    BM_EXTERN_ATTRIBUTE_ADD(%s);\n' % i
                p4_ext_attr_str = p4_ext_attr_str + \
                                  '    attribute %s {\n'\
                                  '        type: string;\n'\
                                  '    }\n'\
                                  % i
            ext_attr_str = ext_attr_str + '  }\n'

        if re.match('extern_methods =', line) and not meth_pres:
            meth_pres = True
            ext_meth = str(re.sub('extern_methods =', '', line))
            ext_meth_ = re.split('\W+', ext_meth.strip())
            ext_meth_str= ''
            p4_ext_meth_str= ''
            for i in ext_meth_:
                ext_meth_str = ext_meth_str + \
                             '  void %s () {\n    // Put your code here\n  }\n'\
                             % i
                p4_ext_meth_str = p4_ext_meth_str + \
                                  '    method %s ();\n'\
                                  % i
    file_.close()
    if name_pres:
        cpp_dump_file = cpp_dump_file % \
                        (ext_name, '%s', '%s', '%s', '%s', '%s', '%s')
        p4_dump_file = p4_dump_file % \
                        (ext_name, '%s', '%s')
    else:
        print("Required extern_type name missing in the config file\n")
        return False
    if attr_pres:
        cpp_dump_file = cpp_dump_file % \
                        (ext_attr_str, '%s', '%s', '%s', '%s', '%s')
        p4_dump_file = p4_dump_file % \
                        (p4_ext_attr_str, '%s')
    else:
        cpp_dump_file = cpp_dump_file % \
                        ('', '%s', '%s', '%s', '%s', '%s')
        p4_dump_file = p4_dump_file % \
                        ('', '%s')
    if meth_pres:
        cpp_dump_file = cpp_dump_file % \
                        (ext_meth_str, '%s', '%s', '%s', '%s')
        p4_dump_file = p4_dump_file % \
                        p4_ext_meth_str
    else:
        cpp_dump_file = cpp_dump_file % \
                        ('', '%s', '%s', '%s', '%s')
        p4_dump_file = p4_dump_file % \
                        ''
    
    if attr_pres:
        ext_attr_str = ''
        for i in ext_attr_:
            ext_attr_str = ext_attr_str + \
                            '  int %s;\n' % i
        cpp_dump_file = cpp_dump_file % \
                        (ext_attr_str, '%s', '%s', '%s')
    else:
        cpp_dump_file = cpp_dump_file % \
                        ('', '%s', '%s', '%s')

    cpp_dump_file = cpp_dump_file % \
                    (ext_name, '%s', '%s')  

    if meth_pres:
        ext_meth_str = ''
        for i in ext_meth_:
            ext_meth_str = ext_meth_str + \
                           'BM_REGISTER_EXTERN_METHOD(%s, %s);\n' % \
                           (ext_name, i)
        cpp_dump_file = cpp_dump_file % \
                        (ext_meth_str, '%s')
    else:
        cpp_dump_file = cpp_dump_file % \
                        ('', '%s')
  
    cpp_dump_file = cpp_dump_file % ext_name
    file_out = open("extern_" + ext_name + ".cpp", "w")
    file_out.write(cpp_dump_file)
    file_out.close()
    file_out = open("extern_" + ext_name + ".p4", "w")
    file_out.write(p4_dump_file)
    file_out.close()
    return True

def main():
    
    if len(sys.argv) != 2:
        param = len(sys.argv) - 1
        print "Invalid parameter number. Expected 1 got %d" % param
        print "Valid parameters: -h and <user_p4_extern>.cfg"
        return
    else:
        if sys.argv[1] == "-h":
            print "Extern P4 compatible template generator"
            print "Creates a C++ class to be called in the target and"\
                  " the equivalent p4 code with the extern type definition"
            print "Usage: python extern_template_gen.py <user_p4_extern>.cfg"
            print "Example of <user_p4_extern>.cfg:"
            print "----- File begin -----"
            print "extern_type = test_extern"
            print "extern_attributes = attr_1 attr_2"
            print "extern_methods =  method_1 method_2"
            print "----- File end -------"
            print "Output files:"
            print "<extern_type>.cpp and <extern_type>.p4:"
            return
        elif os.path.isfile(sys.argv[1]):
            file_config = sys.argv[1]
        else:
            print "Invalid parameter"
            print "Valid parameters: -h or <user_p4_extern>.cfg"
            return 

    if not dump_ext_files(file_config):
        return

if __name__ == '__main__':
    main()

