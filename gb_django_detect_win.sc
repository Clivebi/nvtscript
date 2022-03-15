if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113345" );
	script_version( "2021-05-07T12:04:10+0000" );
	script_tag( name: "last_modification", value: "2021-05-07 12:04:10 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "creation_date", value: "2019-02-27 10:15:22 +0100 (Wed, 27 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Django Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "WMI/access_successful" );
	script_exclude_keys( "win/lsc/disable_win_cmd_exec" );
	script_tag( name: "summary", value: "SMB login-based detection of Django." );
	script_xref( name: "URL", value: "https://www.djangoproject.com/" );
	exit( 0 );
}
CPE = "cpe:/a:djangoproject:django:";
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("cpe.inc.sc");
if(!defined_func( "win_cmd_exec" )){
	exit( 0 );
}
if(get_kb_item( "win/lsc/disable_win_cmd_exec" )){
	exit( 0 );
}
if(kb_smb_is_samba()){
	exit( 0 );
}
port = kb_smb_transport();
if(!port){
	port = 139;
}
if(!get_port_state( port )){
	exit( 0 );
}
username = kb_smb_login();
password = kb_smb_password();
if(!username && !password){
	exit( 0 );
}
func run_command( command, password, username ){
	var command, password, username;
	var serQueryRes;
	serQueryRes = win_cmd_exec( cmd: command, password: password, username: username );
	if( ContainsString( serQueryRes, "Access is denied" ) ){
		return;
	}
	else {
		if( ContainsString( serQueryRes, "The specified service does not exist" ) ){
			return;
		}
		else {
			if( ContainsString( serQueryRes, "The service cannot be started" ) && ContainsString( serQueryRes, "it is disabled" ) ){
				return;
			}
			else {
				if( ContainsString( serQueryRes, "OpenService FAILED" ) && ContainsString( serQueryRes, "specified service does not exist" ) ){
					return;
				}
				else {
					if( ContainsString( serQueryRes, "StartService FAILED" ) ){
						return;
					}
					else {
						if( ContainsString( serQueryRes, "An instance of the service is already running" ) ){
							return;
						}
						else {
							return serQueryRes;
						}
					}
				}
			}
		}
	}
}
domain = kb_smb_domain();
if(domain){
	username = domain + "/" + username;
}
cmd = "cmd /c django-admin --version";
result = run_command( command: cmd, password: password, username: username );
if(isnull( result ) || IsMatchRegexp( result, "not recognized" ) || IsMatchRegexp( result, "not found" )){
	exit( 0 );
}
ver = eregmatch( string: result, pattern: "\n([0-9.]+)" );
if(isnull( ver[1] )){
	exit( 0 );
}
set_kb_item( name: "django/windows/detected", value: TRUE );
register_and_report_cpe( app: "Django", ver: ver[1], concluded: ver[0], base: CPE, expr: "([0-9.]+)", regPort: 0, regService: "smb-login" );
exit( 0 );

