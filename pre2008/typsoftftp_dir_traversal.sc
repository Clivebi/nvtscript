if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14706" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2489 );
	script_cve_id( "CVE-2002-0558" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "TYPSoft directory traversal flaw" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/typsoft/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Use a different FTP server or upgrade to the newest version." );
	script_tag( name: "summary", value: "The remote host seems to be running TYPSoft FTP earlier than 0.97.5

  This version is prone to directory traversal attacks." );
	script_tag( name: "impact", value: "An attacker could send specially crafted URL to view arbitrary
  files on the system." );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: ".*TYPSoft FTP Server (0\\.8|0\\.9[0-6][^0-9]|0\\.97[^0-9]|0\\.97\\.[0-4][^0-9])", string: banner )){
	security_message( port );
}

