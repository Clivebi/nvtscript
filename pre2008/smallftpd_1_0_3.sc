if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12072" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0299" );
	script_bugtraq_id( 9684 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "smallftpd 1.0.3" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2004 Audun Larsen" );
	script_family( "Denial of Service" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/smallftpd/detected" );
	script_tag( name: "summary", value: "The remote host seems to be running smallftpd 1.0.3." );
	script_tag( name: "insight", value: "It has been reported that SmallFTPD is prone to a remote denial of service
  vulnerability. This issue is due to the application failing to properly validate user input." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "smallftpd" )){
	exit( 0 );
}
if(egrep( pattern: "^220.*smallftpd (0\\..*|1\\.0\\.[0-3][^0-9])", string: banner )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

