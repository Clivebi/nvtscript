if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100615" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)" );
	script_bugtraq_id( 39802 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CompleteFTP Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/complete/ftp/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39802" );
	script_tag( name: "summary", value: "CompleteFTP is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue can allow an attacker to download arbitrary
  files outside of the FTP server root directory. This may aid in further attacks." );
	script_tag( name: "affected", value: "CompleteFTP 3.3.0 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = ftp_get_port( default: 21 );
if(!banner = ftp_get_banner( port: port )){
	exit( 0 );
}
if(!ContainsString( banner, "220-Complete FTP server" )){
	exit( 0 );
}
version = eregmatch( pattern: "220 FTP Server v ([0-9.]+)", string: banner );
if(!isnull( version[1] )){
	if(version_in_range( version: version[1], test_version: "3.0.0", test_version2: "3.3.0" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

