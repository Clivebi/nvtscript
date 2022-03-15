if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802230" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IBM Lotus Symphony Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script finds the installed IBM Lotus Symphony version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
use_find = get_kb_item( "ssh/lsc/enable_find" );
if(ContainsString( use_find, "no" )){
	close( sock );
	exit( 0 );
}
if(isnull( use_find )){
	use_find = "yes";
}
descend_directories = get_kb_item( "ssh/lsc/descend_ofs" );
if(isnull( descend_directories )){
	descend_directories = "yes";
}
cmd = "find / -name about.mappings";
if(ContainsString( descend_directories, "no" )){
	cmd += " -xdev";
}
cmd += " -type f";
paths = split( ssh_cmd( socket: sock, cmd: cmd, timeout: 60 ) );
if(paths != NULL){
	for path in paths {
		if(ContainsString( path, "com.ibm.symphony" )){
			file = ssh_cmd( socket: sock, cmd: "cat " + path );
		}
	}
}
close( sock );
ssh_close_connection();
if(isnull( file ) || !ContainsString( file, "Symphony" )){
	exit( 0 );
}
for line in split( file ) {
	version = eregmatch( pattern: "1=([0-9.]+).?([a-zA-Z0-9]+)?", string: line );
	if(version[1] != NULL){
		symVer = version[1];
		if(version[2] != NULL){
			symVer = version[1] + "." + version[2];
		}
		break;
	}
}
if(symVer){
	set_kb_item( name: "IBM/Lotus/Symphony/Lin/Ver", value: symVer );
	log_message( data: "IBM Lotus Symphony version " + symVer + " was detected on the host" );
}

