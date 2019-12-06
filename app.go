package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/clients"
	claas "intel/isecl/lib/clients/aas"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type UserAndRolesCreate struct {
	aas.UserCreate                  //embed
	PrintBearerToken	bool `json:"print_bearer_token"`
	Roles          []aas.RoleCreate `json:"roles"`
}


type AasUsersAndRolesSetup struct {
	AasApiUrl        string               `json:"aas_api_url"`
	AasAdminUserName string               `json:"aas_admin_username"`
	AasAdminPassword string               `json:"aas_admin_password"`
	UsersAndRoles    []UserAndRolesCreate `json:"users_and_roles"`
}

type App struct {
	AasAPIUrl        string
	AasAdminUserName string
	AasAdminPassword string

	VsCN       string
	VsSanList  string
	AhCN       string
	AhSanList  string
	WlsCN      string
	WlsSanList string
	TaCN       string
	TaSanList  string
	KmsCN      string
	KmsSanList string

	InstallAdminUserName   string
	InstallAdminPassword   string
	VsServiceUserName      string
	VsServiceUserPassword  string
	AhServiceUserName      string
	AhServiceUserPassword  string
	WpmServiceUserName     string
	WpmServiceUserPassword string
	WlsServiceUserName     string
	WlsServiceUserPassword string
	WlaServiceUserName     string
	WlaServiceUserPassword string

	Components map[string]bool

	ConsoleWriter io.Writer
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
}

func RandomString(n int) string {
	var letter = []rune("~=+%^*/()[]{}/!@#$?|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	rand.Seed(time.Now().UnixNano())
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

func MakeTlsCertificateRole(cn, san string) aas.RoleCreate {
	r := aas.RoleCreate{}
	r.Service = "CMS"
	r.Name = "CertApprover"
	r.Context = "CN=" + cn + ";SAN=" + san + "certType=TLS"
	return r
}

func NewRole(service, name, context string, perms []string) aas.RoleCreate {
	//r := aas.RoleCreate{aas.RoleInfo{Service: service, Name: name, Context: context}, Permissions:{}}
	r := aas.RoleCreate{}
	r.Service = service
	r.Name = name
	r.Context = context
	if len(perms) > 0 {
		r.Permissions = append([]string(nil), perms...)
	}
	return r
}

func (a* App) GetServiceUsers() []UserAndRolesCreate {

	urs := []UserAndRolesCreate{}
	for k, _ := range a.Components{

		urc := UserAndRolesCreate{}
		urc.Roles = []aas.RoleCreate{}

		switch(k){
		case "VS":
			urc.Name = a.VsServiceUserName
			urc.Password = a.VsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("TA", "Administrator", "", []string{"*:*:*"}))
		case "AH":
			urc.Name = a.AhServiceUserName
			urc.Password = a.AhServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("VS", "ReportRetriever", "", []string{"reports:retrieve:*","reports:search:*","hosts:search:*","hosts:retrieve:*"}))
		case "WPM":
			urc.Name = a.WpmServiceUserName
			urc.Password = a.WpmServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("VS", "KeyManager", "", []string{"keys:create:*","keys:transfer:*"}))
		case "WLS":
			urc.Name = a.WlsServiceUserName
			urc.Password = a.WlsServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("KMS", "ReportCreater", "", []string{"reports:create:*"}))
		case "WLA":
			urc.Name = a.WlaServiceUserName
			urc.Password = a.WlaServiceUserPassword
			urc.Roles = append(urc.Roles, NewRole("WLS", "FlavorsImageRetrieval", "",nil))
			urc.Roles = append(urc.Roles, NewRole("WLS", "ReportsCreate", "",nil))
		}
		urs = append(urs, urc)

	}
	return urs

}

func (a *App) GetSuperInstallUser() UserAndRolesCreate {

	// set the user
	urc := UserAndRolesCreate{}
	urc.Name = a.InstallAdminUserName
	urc.Password = a.InstallAdminPassword
	urc.PrintBearerToken = true
	if urc.Password == "" {
		urc.Password = RandomString(20)
	}

	urc.Roles = []aas.RoleCreate{}

	// set the roles depending on the components that are to be installed
	
	for k, _ := range a.Components{
		switch(k){
		case "VS": 
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=VS Flavor Signing Certificate;certType=Signing", nil))
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.VsCN, a.VsSanList))
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=mtwilson-saml;certType=Signing", nil))
		case "TA":
			urc.Roles = append(urc.Roles, NewRole("VS", "AttestationRegister", "CN=mtwilson-saml;certType=Signing",
						[]string{"host_tls_policies:create:*","hosts:create:*","hosts:store:*","hosts:search:*",
						"host_unique_flavors:create:*","flavors:search:*", "tpm_passwords:retrieve:*",
						"tpm_passwords:create:*", "host_aiks:certify:*"}))
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.TaCN, a.TaSanList))
		case "AH":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.AhCN, a.AhSanList))
			urc.Roles = append(urc.Roles, NewRole("VS", "CaCertRetriever", "", []string{"*:*:*"}))
		case "KBS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.KmsCN, a.KmsSanList))
			urc.Roles = append(urc.Roles, NewRole("VS", "CaCertRetriever", "", []string{"*:*:*"}))

		case "WPM":
			urc.Roles = append(urc.Roles, NewRole("CMS", "CertApprover", "CN=WPM Flavor Signing Certificate;certType=Signing", nil))
		case "WLS":
			urc.Roles = append(urc.Roles, MakeTlsCertificateRole(a.WlsCN, a.WlsSanList))
		case "WLA":
			urc.Roles = append(urc.Roles, NewRole("VS", "Certifier", "", []string{"host_signing_key_certificates:create:*"}))
		}
	}


	return urc

}

func SetVariable(variable *string, envVarName string, defaultVal string, desc string, mandatory bool, secret bool) error {
	if *variable = os.Getenv(envVarName); *variable == "" {
		if mandatory {
			fmt.Println(envVarName, "-", desc, " is mandatory and cannot be empty")
			return fmt.Errorf("required environment variable missing")
		}

	}
	if *variable == "" && defaultVal != "" {
		*variable = defaultVal
	}

	if secret {
		fmt.Println(desc, "= *******")
	} else {
		fmt.Println(desc, "=", *variable)
	}

	return nil
}

func (a *App) LoadAllVariables(envFile string) error {
	if err := godotenv.Load(envFile); err != nil {
		fmt.Println("could not load environment file :", envFile, ". Will be using existing exported environement variables")
	}

	// mandatory variables

	var installComps string

	type envDesc struct {
		variable    *string
		envVarName  string
		defaultVal  string
		description string
		mandatory   bool
		secret      bool
	}

	envVars := []envDesc{
		{&a.AasAPIUrl, "AAS_API_URL", "", "AAS API URL", true, false},
		{&a.AasAdminUserName, "AAS_ADMIN_USERNAME", "", "AAS ADMIN USERNAME", true, false},
		{&a.AasAdminPassword, "AAS_ADMIN_PASSWORD", "", "AAS ADMIN PASSWORD", true, true},

		{&installComps, "ISECL_INSTALLED_COMPONENTS", "", "ISecl Components to be installed", true, true},

		{&a.InstallAdminUserName, "INSTALL_ADMIN_USERNAME", "installadmin", "AAS ADMIN USERNAME", false, false},
		{&a.InstallAdminPassword, "INSTALL_ADMIN_PASSWORD", "", "AAS ADMIN PASSWORD", false, true},

		{&a.VsCN, "VS_CERT_COMMON_NAME", "Mt Wilson TLS Certificate", "Verification Service TLS Certificate Common Name", false, false},
		{&a.VsSanList, "VS_CERT_SAN_LIST", "", "Verification Service TLS Certificate SAN LIST", false, false},

		{&a.AhCN, "AH_CERT_COMMON_NAME", "Attestation Hub TLS Certificate", "Attestation Hub TLS Certificate Common Name", false, false},
		{&a.AhSanList, "AH_CERT_SAN_LIST", "", "Attestation Hub TLS Certificate SAN LIST", false, false},

		{&a.WlsCN, "WLS_CERT_COMMON_NAME", "WLS TLS Certificate", "Workload Service TLS Certificate Common Name", false, false},
		{&a.WlsSanList, "WLS_CERT_SAN_LIST", "", "Workload Service TLS Certificate SAN LIST", false, false},

		{&a.KmsCN, "KMS_CERT_COMMON_NAME", "KMS TLS Certificate", "Key Broker Service TLS Certificate Common Name", false, false},
		{&a.KmsSanList, "KMS_CERT_SAN_LIST", "", "Key Broker Service TLS Certificate SAN LIST", false, false},

		{&a.TaCN, "TA_CERT_COMMON_NAME", "Trust Agent TLS Certificate", "Trust Agent TLS Certificate Common Name", false, false},
		{&a.TaSanList, "TA_CERT_SAN_LIST", "", "Trust Agent TLS Certificate SAN LIST", false, false},

		{&a.VsServiceUserName, "VS_SERVICE_USERNAME", "", "Verificaiton Service User Name", false, false},
		{&a.VsServiceUserPassword, "VS_SERVICE_PASSWORD", "", "Verification Service User Password", false, true},

		{&a.AhServiceUserName, "AH_SERVICE_USERNAME", "", "Attestation Hub Service User Name", false, false},
		{&a.AhServiceUserPassword, "VS_SERVICE_PASSWORD", "", "Attestation Hub Service User Password", false, true},

		{&a.WpmServiceUserName, "WPM_SERVICE_USERNAME", "", "Workload Policy Manager Hub Service User Name", false, false},
		{&a.WpmServiceUserPassword, "WPM_SERVICE_PASSWORD", "", "Workload Policy Manager Service User Password", false, true},

		{&a.WlsServiceUserName, "WLS_SERVICE_USERNAME", "", "Workload Service User Name", false, false},
		{&a.WlsServiceUserPassword, "WLS_SERVICE_PASSWORD", "", "Workload Service User Password", false, true},

		{&a.WlaServiceUserName, "WLA_SERVICE_USERNAME", "", "Workload Service User Name", false, false},
		{&a.WlaServiceUserPassword, "WLA_SERVICE_PASSWORD", "", "Workload Service User Password", false, true},
	}

	hasError := false

	for _, envVar := range envVars {
		if err := SetVariable(envVar.variable, envVar.envVarName, envVar.defaultVal, envVar.description, envVar.mandatory, envVar.secret); err != nil {
			hasError = true
		}
	}
	if hasError {
		return fmt.Errorf("Missing Required Environment variable(s). Set these in the env file or export them and run again")
	}

	// set up the app map with components that need to be installed
	slc := strings.Split(installComps, ",")
	a.Components = make(map[string]bool)
	for i := range slc {
		a.Components[strings.TrimSpace(slc[i])] = true
	}

	return nil

}

func (a *App) LoadUserAndRolesJson(file string) (*AasUsersAndRolesSetup, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read user role files %s : ", file)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var urc AasUsersAndRolesSetup
	if err := dec.Decode(&urc); err != nil {
		return nil, fmt.Errorf("could not decode json file for user roles - err", err)
	}
	return &urc, nil
}

func (a* App) GetNewOrExistingUserID(name, password string, aascl *claas.Client) (string, error) {
	
	users, err := aascl.GetUsers(name)
	if err != nil {
		return "", err
	}
	if len(users) == 0 {
		// did not find the user.. so let us create the user.
		newUser, err := aascl.CreateUser(aas.UserCreate{name, password})
		if err != nil {
			return "", err
		}
		return newUser.ID, nil
	}
	if len(users) == 1 && users[0].Name == name {
		// found single record that corresponds to the user. 
		return users[0].ID, nil
	}
	// we should not really be here.. we have multiple users with matched name
	return "", fmt.Errorf("Multiple records found when searching for user %s - record - %v", name, users)
}

func (a* App) GetNewOrExistingRoleID(role aas.RoleCreate, aascl *claas.Client) (string, error) {
	roles, err := aascl.GetRoles(role.Service, role.Name, role.Context, "",false)
	if err != nil {
		return "", err
	}

	if len(roles) == 0 {
		// did not find the role.. so create the role
		newRole, err := aascl.CreateRole(role)
		if err != nil {
			return "", err
		}
		return newRole.ID, nil
	}
	if len(roles) != 1{
		// we should not really be here.. we have multiple users with matched name
		return "", fmt.Errorf("Multiple records found when searching for role %c - record - %v", role)
	}

	// found single record that corresponds to the user. 
	return roles[0].ID, nil

}


func (a* App) AddUsersAndRoles(asr * AasUsersAndRolesSetup) error {

	// first create a JWT token for the admin
	jwtcl := claas.NewJWTClient(asr.AasApiUrl)
	jwtcl.HTTPClient = clients.HTTPClientTLSNoVerify()

	jwtcl.AddUser(asr.AasAdminUserName, asr.AasAdminPassword)
	err := jwtcl.FetchAllTokens()
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	
	token, err := jwtcl.GetUserToken(asr.AasAdminUserName)
	if err != nil {
		return fmt.Errorf("Could not obtain token for %s from %s - err - %s", asr.AasAdminUserName, asr.AasApiUrl, err)

	}

	aascl := claas.Client{asr.AasApiUrl, token, clients.HTTPClientTLSNoVerify()} 
	// no create an aas client with the token. 


	//fmt.Println("BEARER_TOKEN="+string(token))
	for _, user := range asr.UsersAndRoles {
		userid := ""
		if userid, err = a.GetNewOrExistingUserID(user.Name, user.Password, &aascl); err == nil {
			fmt.Println("user:", user.Name, "userid:", userid)
		} else {
			return fmt.Errorf("Error while attempting to create/ retrieve user %s - error %v ", user.Name, err)
			
		}
		// we might have the same role appear more than one in the list of roles to be added for a user
		// since different components might need the same roles. The Add user to role function relies on 
		// having a unique list of roles. put the roleids into a map and then make a list. 

		roleMap := make(map[string]bool)
		for _, role := range user.Roles {
			if roleid, err := a.GetNewOrExistingRoleID(role, &aascl); err == nil {
				fmt.Println("role:", role, "userid:", roleid)
				roleMap[roleid] = true
			} else {
				return fmt.Errorf("Error while attempting to create/ retrieve role %s - error %v ", role.Name, err)
			}

		}
		roleList := []string{}
		for key, _ := range roleMap{
			roleList = append(roleList, key)
		}

		fmt.Println("Roles to added :", roleList)
		if err = aascl.AddRoleToUser(userid, aas.RoleIDs{roleList}); err != nil {
			return fmt.Errorf("Could not add roles to user - %s", user.Name)
		}

		
	}
	return nil

}

func (a *App) Setup(args []string) error {
	var err error
	setup := true
	var noSetup, useJson, outputJson bool
	var envFile, jsonInput, jsonOutput string
	var flags []string

	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.BoolVar(&noSetup, "nosetup", false, "Don't run the setup")
	fs.StringVar(&envFile, "envfile", "./usermanager.env", "Environment file for user manager input")
	fs.BoolVar(&useJson, "use_json", false, "Use Json file instead of parsing env file")
	fs.StringVar(&jsonInput, "in_json_file", "", "Input Json file - will use this file to create ")
	fs.StringVar(&jsonOutput, "out_json_file", "./aas_users_n_roles.json", "Output json file")
	fs.BoolVar(&outputJson, "output_json", false, "Write user and roles to json file")

	err = fs.Parse(flags)
	if err != nil {
		// return err
		return fmt.Errorf("cold not parse the flags")
	}

	var as *AasUsersAndRolesSetup

	if useJson || jsonInput != "" {
		// do what is needed to parse the JSON file to create user and roles
		if jsonInput == "" {
			jsonInput = "./aas_users_n_roles.json"
		}
		if as, err = a.LoadUserAndRolesJson(jsonInput); err != nil {
			fmt.Println(err)
			return err
		}

	} else {
		// call the method to load all the environment variable values
		fmt.Println("Loading environment variables")
		if err := a.LoadAllVariables(envFile); err != nil {
			fmt.Println("Could not find necessary environemnt variables - err ", err)
			return fmt.Errorf("Could not complete Setup. Exiting")
		}
		as = &AasUsersAndRolesSetup{AasApiUrl: a.AasAPIUrl, AasAdminUserName: a.AasAdminUserName, AasAdminPassword: a.AasAdminPassword}
		as.UsersAndRoles = append(as.UsersAndRoles, a.GetSuperInstallUser())
		as.UsersAndRoles = append(as.UsersAndRoles, a.GetServiceUsers()...)

	}
	

	if noSetup {
		setup = false
	}

	if setup {
		fmt.Println("Calling the Setup method")
		if err = a.AddUsersAndRoles(as); err != nil {
			return err
		}
	}
	return nil

}
func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}

	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
	case "setup":
		if err := a.Setup(args[2:]); err != nil {
			fmt.Println("setup not completed successfully. error -", err )
			return err
		}
	}

	return nil
}
