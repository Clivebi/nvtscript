if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100731" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)" );
	script_bugtraq_id( 41987 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Wing FTP Server Denial of Service Vulnerability and Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/wing/ftp/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41987" );
	script_xref( name: "URL", value: "http://www.wftpserver.com/serverhistory.htm" );
	script_tag( name: "summary", value: "Wing FTP Server is prone to a denial-of-service vulnerability and an
  information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to gain access to sensitive
  information or crash the affected application. Other attacks are also possible." );
	script_tag( name: "affected", value: "Versions prior to Wing FTP Server 3.6.1 are vulnerable." );
	script_tag( name: "solution", value: "The vendor released an update. Please see the references for more
  information." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(!ContainsString( banner, "220 Wing FTP Server" )){
	exit( 0 );
}
version = eregmatch( pattern: "Wing FTP Server ([^ ]+) ready", string: banner );
if(!isnull( version[1] )){
	if(version_is_less( version: version[1], test_version: "3.6.1" )){
		report = report_fixed_ver( installed_version: version[1], fixed_version: "3.6.1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

