if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14800" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 11243 );
	script_cve_id( "CVE-2004-0749" );
	script_name( "Subversion Module unreadeable path information disclosure" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Remote file access" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/subversion" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to subversion 1.0.8, 1.1.0-rc4 or newer." );
	script_tag( name: "summary", value: "You are running a version of Subversion which is older than 1.0.8 or 1.1.0-rc4.

  A flaw exists in older version, in the apache module mod_authz_svn,
  which fails to properly restrict access to metadata within unreadable paths." );
	script_tag( name: "impact", value: "An attacker can read metadata in unreadable paths, which can contain sensitive
  information such as logs and paths." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 3690, proto: "subversion" );
dat = NASLString( "( 2 ( edit-pipeline ) 24:svn://host/svn/OpenVASr0x ) " );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = recv_line( socket: soc, length: 1024 );
if(!r){
	exit( 0 );
}
send( socket: soc, data: dat );
r = recv_line( socket: soc, length: 256 );
close( soc );
if(!r){
	exit( 0 );
}
if(egrep( string: r, pattern: ".*subversion-1\\.(0\\.[0-7][^0-9]|1\\.0-rc[1-3][^0-9]).*" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

