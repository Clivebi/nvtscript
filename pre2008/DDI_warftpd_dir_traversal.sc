if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11206" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2444 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-0295" );
	script_name( "War FTP Daemon Directory Traversal" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Digital Defense, Inc." );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/war_ftpd/detected" );
	script_tag( name: "solution", value: "Visit the referenced link and download the latest version of WarFTPd." );
	script_tag( name: "summary", value: "The version of WarFTPd running on this host contains a vulnerability that
  may allow a potential intruder to gain read access to directories and files
  outside of the ftp root. By sending a specially crafted 'dir' command,
  the server may disclose an arbitrary directory." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
r = ftp_get_banner( port: port );
if(!r){
	exit( 0 );
}
if(egrep( pattern: "WAR-FTPD 1\\.(6[0-5]|[0-5].*)", string: r ) || ContainsString( r, "WAR-FTPD 1.67-04" )){
	security_message( port: port );
}

