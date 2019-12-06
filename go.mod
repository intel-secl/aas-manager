module intel/isecl/tools/aas-manager

go 1.12

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients v0.0.0
	intel/isecl/lib/common v0.0.0
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v0.0.0-20191203182738-e076ea0c08ff

//replace intel/isecl/lib/clients => gitlab.devtools.intel.com/sst/isecl/lib/clients.git v0.0.0-20191108060721-afc51eaae3b9
replace intel/isecl/lib/clients => ../../lib/clients/
