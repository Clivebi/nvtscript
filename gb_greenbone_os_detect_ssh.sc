if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112136" );
	script_version( "2020-10-08T08:12:30+0000" );
	script_tag( name: "last_modification", value: "2020-10-08 08:12:30 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2017-11-23 10:47:05 +0100 (Thu, 23 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gather-package-list.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_tag( name: "summary", value: "SSH based detection of the Greenbone Security Manager (GSM) / Greenbone OS (GOS)." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
if(get_kb_item( "greenbone/gos" )){
	uname = get_kb_item( "greenbone/gos/uname" );
	if(uname){
		set_kb_item( name: "greenbone/gos/detected", value: TRUE );
		set_kb_item( name: "greenbone/gos/ssh/detected", value: TRUE );
		set_kb_item( name: "greenbone/gos/ssh/port", value: port );
		version = "unknown";
		vers = eregmatch( pattern: "Welcome to the Greenbone OS ([^ ]+) ", string: uname );
		if( !isnull( vers[1] ) && IsMatchRegexp( vers[1], "^([0-9.-]+)$" ) ){
			version = vers[1];
			concluded = vers[0];
		}
		else {
			banner = egrep( pattern: "^Welcome to the Greenbone OS.*", string: uname );
			if(banner){
				sock = ssh_login_or_reuse_connection();
				cmd = "gsmctl info gsm-info.full_version";
				gsm_info = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: FALSE );
				if(gsm_info && IsMatchRegexp( gsm_info, "^([0-9.]+)$" )){
					version = gsm_info;
					concluded += "\nCommand: " + cmd;
				}
			}
		}
		type = "unknown";
		_type = eregmatch( pattern: "running on a Greenbone Security Manager ([^ \r\n]+)", string: uname );
		if( _type[1] ){
			type = _type[1];
			concluded += _type[0];
		}
		else {
			sock = ssh_login_or_reuse_connection();
			cmd = "gsmctl info gsm-info.type";
			gsm_info = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: FALSE );
			if(gsm_info && IsMatchRegexp( gsm_info, "^([a-zA-Z0-9.]+)$" )){
				type = toupper( gsm_info );
				concluded += "\nCommand: " + cmd;
			}
		}
		set_kb_item( name: "greenbone/gsm/ssh/" + port + "/type", value: type );
		set_kb_item( name: "greenbone/gos/ssh/" + port + "/version", value: version );
		if(concluded){
			set_kb_item( name: "greenbone/gos/ssh/" + port + "/concluded", value: concluded );
		}
		exit( 0 );
	}
}
banner = ssh_get_serverbanner( port: port );
if(banner && ContainsString( banner, "Greenbone OS" )){
	set_kb_item( name: "greenbone/gos/detected", value: TRUE );
	set_kb_item( name: "greenbone/gos/ssh/detected", value: TRUE );
	set_kb_item( name: "greenbone/gos/ssh/port", value: port );
	vers = eregmatch( pattern: "Greenbone OS ([0-9.-]+)", string: banner );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "greenbone/gos/ssh/" + port + "/version", value: version );
		set_kb_item( name: "greenbone/gos/ssh/" + port + "/concluded", value: banner );
	}
}
exit( 0 );

