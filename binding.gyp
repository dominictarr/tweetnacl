{
  'variables': {
        'target_arch%': '<!(node -e \"var os = require(\'os\'); console.log(os.arch());\")>'},

        'targets': [
            {
                  'target_name': 'nodetweetnacl',
                  'sources': [
                        'tweetnacl.c',
                        'nodetweetnacl.cc'
                  ],
                  'include_dirs': [
                        "./",
                       "<!(node -e \"require('nan')\")"
                  ],
                  'cflags!': [ '-fno-exceptions' ],
                  
            }
      ]
}
