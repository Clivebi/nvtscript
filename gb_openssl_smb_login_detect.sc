if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800257" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "OpenSSL Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc", "lsc_options.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of OpenSSL." );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
require("policy_functions.inc.sc");
port = kb_smb_transport();
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
detected = FALSE;
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		app_name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!app_name || !IsMatchRegexp( app_name, "^OpenSSL" )){
			continue;
		}
		detected = TRUE;
		reg_concluded = "Registry Key:    " + key + item + "\n";
		reg_concluded += "DisplayName:     " + app_name;
		if(disp_vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			reg_concluded += "\nDisplayVersion:  " + disp_vers + " (Note: This version doesn't reflect the actual installed version)";
		}
		break;
	}
}
if(!detected){
	exit( 0 );
}
set_kb_item( name: "openssl/detected", value: TRUE );
set_kb_item( name: "openssl_or_gnutls/detected", value: TRUE );
set_kb_item( name: "openssl/smb-login/detected", value: TRUE );
version = "unknown";
location = "unknown";
if(get_kb_item( "win/lsc/disable_wmi_search" )){
	set_kb_item( name: "openssl/smb-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + reg_concluded + "#---#WMI search disabled in the scan config, location and version extraction not possible." );
	exit( 0 );
}
infos = kb_smb_wmi_connectinfo();
if(infos){
	handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
	if(!handle){
		set_kb_item( name: "openssl/smb-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + reg_concluded + "#---#No WMI connection to the host, location and version extraction not possible." );
		exit( 0 );
	}
}
file_list = wmi_file_file_search( handle: handle, fileName: "openssl", fileExtn: "exe", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!file_list || !is_array( file_list )){
	set_kb_item( name: "openssl/smb-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + reg_concluded + "#---#Failed to find an openssl.exe file via WMI, location and version extraction not possible." );
	exit( 0 );
}
for file in file_list {
	if(!file || !ContainsString( tolower( file ), "\\openssl.exe" )){
		continue;
	}
	split = split( buffer: file, sep: "\\" );
	count = max_index( split ) - 1;
	file_name = split[count];
	location = ereg_replace( string: file, pattern: split[max_index( split ) - 1], replace: "" );
	file_vers = fetch_file_version( sysPath: location, file_name: file_name );
	if(file_vers){
		concluded = "File version:    " + file_vers + " fetched from " + location + file_name;
	}
	file = location + file_name;
	cmd = "(get-item '" + file + "').VersionInfo | select ProductVersion | ft -HideTableHeaders";
	value = policy_powershell_cmd( cmd: cmd );
	if(value){
		version = value;
		concluded += "\nProduct version: " + version + " fetched from the executable with PowerShell.";
	}
	set_kb_item( name: "openssl/smb-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + concluded + "\n" + reg_concluded );
}
exit( 0 );

