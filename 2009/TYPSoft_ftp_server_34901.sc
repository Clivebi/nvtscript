if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100198" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1668" );
	script_bugtraq_id( 34901 );
	script_name( "TYPSoft FTP Server 'ABORT' Command Remote Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/typsoft/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34901" );
	script_tag( name: "summary", value: "TYPSoft FTP Server is prone to a remote denial-of-service
  vulnerability." );
	script_tag( name: "impact", value: "This issue allows remote attackers to cause the affected server to
  stop responding, denying service to legitimate users." );
	script_tag( name: "affected", value: "TYPSoft FTP Server 1.11 is vulnerable. Other versions may also be
  affected." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
if(!ContainsString( banner, "TYPSoft FTP Server" )){
	exit( 0 );
}
version = eregmatch( pattern: "TYPSoft FTP Server ([0-9.]+)", string: banner );
if(!isnull( version[1] )){
	if(version_is_less_equal( version: version[1], test_version: "1.11" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

