if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100690" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-23 13:22:49 +0200 (Wed, 23 Jun 2010)" );
	script_bugtraq_id( 41015 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Wing FTP Server 'PORT' Command Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/wing/ftp/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41015" );
	script_xref( name: "URL", value: "http://www.wftpserver.com/serverhistory.htm" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/511905" );
	script_xref( name: "URL", value: "http://blog.trendmicro.com/trend-micro-discovers-wing-ftp-server-port-command-dos-bug/" );
	script_tag( name: "summary", value: "Wing FTP Server is prone to a denial-of-service vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause the server to crash,
  resulting in a denial-of-service condition. Other attacks may also be possible." );
	script_tag( name: "affected", value: "Wing FTP Server 3.1.2 is vulnerable. Prior versions may also be
  affected.

  This issue is known to be exploitable in Windows environment. Other platforms may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
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
if(!ContainsString( banner, "220 Wing FTP Server" )){
	exit( 0 );
}
version = eregmatch( pattern: "Wing FTP Server ([^ ]+) ready", string: banner );
if(!isnull( version[1] )){
	if(version_is_less( version: version[1], test_version: "3.2" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

