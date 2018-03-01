import os
import re
import sys

# TODO: cleanup... lots of cleanup
lines = sys.stdin.read().splitlines()
lines = [line for line in lines if not line.startswith('#') and line != '']

print "const unsigned int nr_mutations = %u;" % (len(lines), )

print "static node_ptr mutate(node_ptr root, node_ptr leaf, unsigned int mutation)"
print "{"
print "\tauto replacement = std::make_shared<node>();"
print "\tswitch (mutation) {"

for i, line in enumerate(lines):
    print "\tcase %u:" % (i, )

    for word in re.split(r'((?<!\\)\[.*?(?<!\\)\])', line[1:-1]):
        if word.startswith('['):
            word = re.sub(r'\\([\[\]])', r'\1', word[1:-1])
            print "\t\treplacement->children.push_back(std::make_shared<node>(\"%s\"));" % (word, )
        else:
            word = re.sub(r'\\([\[\]])', r'\1', word)
            print "\t\treplacement->children.push_back(std::make_shared<node>(\"%s\", true));" % (word, )

    print "\t\tbreak;"

print "\t}"
print "\treturn replace(root, leaf, replacement);"
print "}"
