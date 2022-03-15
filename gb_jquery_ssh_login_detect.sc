if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150657" );
	script_version( "2021-06-17T12:57:07+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 12:57:07 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-02 14:44:56 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "jQuery Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of jQuery." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
files = ssh_find_file( file_name: "/jquery[-.]?([0-9.]+)?(\\.min|\\.slim|\\.slim\\.min)?\\.js$", useregex: TRUE, sock: sock );
if(!files){
	ssh_close_connection();
	exit( 0 );
}
found = FALSE;
for file in files {
	file = chomp( file );
	if(!file || !ContainsString( file, "/jquery" )){
		continue;
	}
	version = "unknown";
	vers = eregmatch( string: file, pattern: "jquery[-.]?([0-9.]+)?(\\.min|\\.slim|\\.slim\\.min)?\\.js" );
	if(vers[1]){
		version = vers[1];
	}
	if(version == "unknown"){
		content = ssh_cmd( socket: sock, cmd: "cat " + file );
		if(!content){
			continue;
		}
		vers = eregmatch( pattern: "jQuery (JavaScript Library )?v([0-9.]+)", string: content, icase: FALSE );
		if(vers[2]){
			version = vers[2];
		}
		if(version == "unknown" && ContainsString( content, "jQuery requires a window with a document" )){
			vers = eregmatch( pattern: "version\\s*=\\s*[\"\']?([0-9.]+)", string: content, icase: FALSE );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
	}
	if(version != "unknown"){
		found = TRUE;
		set_kb_item( name: "jquery/ssh-login/" + port + "/installs", value: "0#---#" + file + "#---#" + version + "#---#" + vers[0] );
	}
}
if(found){
	set_kb_item( name: "jquery/detected", value: TRUE );
	set_kb_item( name: "jquery/ssh-login/detected", value: TRUE );
}
ssh_close_connection();
exit( 0 );

