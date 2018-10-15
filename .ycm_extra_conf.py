import os
from glob import glob
#import ycm_core

base = os.path.dirname(os.path.abspath(__file__))

def FlagsForFile(filename, **kwargs):
	filedir = os.path.dirname(filename)
	flags = [
		'-x', 'c++',
		'-Wall',
		'-Wextra',
		'-Wpedantic',
		'-fPIC',
		'-std=c++17',
		'-isystem', os.path.join(base, 'include/ldapxx'),
	]

	return {
		'flags': flags,
		'do_cache': True
	}

