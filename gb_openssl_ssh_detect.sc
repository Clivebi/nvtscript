if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117244" );
	script_version( "2021-03-12T12:00:12+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-12 12:00:12 +0000 (Fri, 12 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-12 11:29:29 +0000 (Fri, 12 Mar 2021)" );
	script_name( "OpenSSL Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/openssl/detected" );
	script_tag( name: "summary", value: "SSH based detection of OpenSSL." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(banner && concl = egrep( string: banner, pattern: "^SSH-.+OpenSSL", icase: TRUE )){
	concl = chomp( concl );
	version = "unknown";
	install = port + "/tcp";
	vers = eregmatch( pattern: "SSH-.+OpenSSL ([0-9.a-z]+)", string: concl, icase: TRUE );
	if(vers[1] && !ContainsString( vers[0], "OpenSSL 0x" )){
		version = vers[1];
	}
	set_kb_item( name: "openssl/detected", value: TRUE );
	set_kb_item( name: "openssl/ssh/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + concl );
	set_kb_item( name: "openssl/ssh/detected", value: TRUE );
	set_kb_item( name: "openssl/ssh/port", value: port );
}
exit( 0 );

