if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804405" );
	script_version( "$Revision: 11420 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-04-03 15:54:53 +0530 (Thu, 03 Apr 2014)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Subversion Server Detection Version Detection" );
	script_tag( name: "summary", value: "Detection of Subversion Server version.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/subversion", 3690 );
	exit( 0 );
}
require("cpe.inc.sc");
require("ftp_func.inc.sc");
require("host_details.inc.sc");
subPort = get_kb_item( "Services/subversion" );
if(!subPort){
	subPort = 3690;
}
if(!get_tcp_port_state( subPort )){
	exit( 0 );
}
soc = open_sock_tcp( subPort );
if(!soc){
	exit( 0 );
}
resp = recv( socket: soc, length: 4096 );
if(IsMatchRegexp( resp, "^\\( success \\( [0-9] [0-9] \\(.*\\) \\(.*" )){
	send( socket: soc, data: "( 2 ( edit-pipeline ) 24:svn://host/svn/OpenVAS0x ) \\r\\n" );
	resp = recv( socket: soc, length: 4096 );
	subVer = eregmatch( pattern: ".*subversion-([0-9.]+)", string: resp );
	if(subVer[1]){
		set_kb_item( name: "Subversion/Server/Ver", value: subVer[1] );
		set_kb_item( name: "Subversion/installed", value: TRUE );
		cpe = build_cpe( value: subVer[1], exp: "^([0-9.]+)", base: "cpe:/a:apache:subversion:" );
		if(!cpe){
			cpe = "cpe:/a:apache:subversion";
		}
		register_product( cpe: cpe, location: "/", port: subPort );
		log_message( data: build_detection_report( app: "Subversion Server", version: subVer[1], install: "/", cpe: cpe, concluded: subVer[1] ), port: subPort );
	}
}
close( soc );

