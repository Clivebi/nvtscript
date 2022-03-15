if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108472" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-17 08:43:06 +0200 (Wed, 17 Oct 2018)" );
	script_name( "libssh SSH Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/libssh/detected" );
	script_xref( name: "URL", value: "https://www.libssh.org" );
	script_tag( name: "summary", value: "The script sends a connection request to a remote SSH server
  and attempts to identify if it is using libssh and its version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(banner && IsMatchRegexp( banner, "^SSH-.*libssh" )){
	version = "unknown";
	vers = eregmatch( pattern: "^SSH-.*libssh[_-]([0-9.]+)", string: banner );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "libssh/server/detected", value: TRUE );
	register_and_report_cpe( app: "libssh Server", ver: version, concluded: banner, base: "cpe:/a:libssh:libssh:", expr: "^([0-9.]+)", regPort: port, insloc: port + "/tcp" );
}
exit( 0 );

