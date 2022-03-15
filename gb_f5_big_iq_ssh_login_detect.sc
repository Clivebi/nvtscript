if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105164" );
	script_version( "2021-05-27T10:27:30+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-27 10:27:30 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2015-01-12 14:32:58 +0100 (Mon, 12 Jan 2015)" );
	script_name( "F5 Networks BIG-IQ Detection (SSH Login)" );
	script_tag( name: "summary", value: "SSH login-based detection of F5 Networks BIG-IQ." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "f5/big_iq/VERSION_RAW" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
infos = get_kb_item( "f5/big_iq/VERSION_RAW" );
if(!infos || !ContainsString( infos, "Product: BIG-IQ" )){
	exit( 0 );
}
port = get_kb_item( "f5/big_iq/ssh-login/port" );
if(get_kb_item( "f5/shell_is_tmsh" )){
	nosh = TRUE;
}
set_kb_item( name: "f5/big_iq/detected", value: TRUE );
set_kb_item( name: "f5/big_iq/ssh-login/detected", value: TRUE );
_version = "unknown";
_build = "unknown";
version = eregmatch( pattern: "Version: ([^\r\n]+)", string: infos );
build = eregmatch( pattern: "Build: ([^\r\n]+)", string: infos );
built = eregmatch( pattern: "Built: ([^\r\n]+)", string: infos );
edition = eregmatch( pattern: "Edition: ([^\r\n]+)", string: infos );
changelist = eregmatch( pattern: "Changelist: ([^\r\n]+)", string: infos );
if(!isnull( version[1] )){
	_version = version[1];
}
if(!isnull( build[1] )){
	_build = build[1];
}
if(!isnull( edition[1] )){
	set_kb_item( name: "f5/big_iq/edition", value: edition[1] );
}
if(!isnull( built[1] )){
	set_kb_item( name: "f5/big_iq/built", value: built[1] );
}
if(!isnull( changelist[1] )){
	set_kb_item( name: "f5/big_iq/changelist", value: changelist[1] );
}
if( nosh ) {
	modules_cmd = ssh_cmd_exec( cmd: "list sys provision", nosh: TRUE );
}
else {
	modules_cmd = ssh_cmd_exec( cmd: "tmsh list sys provision" );
}
if(!isnull( modules_cmd )){
	modules_lines = split( modules_cmd );
	for(i = 0;i < max_index( modules_lines );i++){
		if(ContainsString( modules_lines[i], "{ }" )){
			continue;
		}
		if(module = eregmatch( pattern: "sys provision ([^ \r\n{]+) \\{[\r\n]+", string: modules_lines[i] )){
			active_modules += module[1] + ",";
		}
	}
}
if(IsMatchRegexp( active_modules, ",$" )){
	active_modules = ereg_replace( pattern: "(,)$", replace: "", string: active_modules );
}
active_modules = toupper( active_modules );
if(active_modules){
	set_kb_item( name: "f5/big_iq/active_modules", value: active_modules );
}
set_kb_item( name: "f5/big_iq/ssh-login/" + port + "/version", value: _version );
set_kb_item( name: "f5/big_iq/ssh-login/" + port + "/build", value: _build );
exit( 0 );

