if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801970" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "SurgeFTP Admin Multiple Reflected Cross-site Scripting Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/surgeftp/detected" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/104047/surgeftp3b6-xss.txt" );
	script_xref( name: "URL", value: "http://www.securityhome.eu/os/winnt/exploit.php?eid=8349105614e4a2458040b68.10913730" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary html or scripting code in a user's browser session in the context of a vulnerable application/website." );
	script_tag( name: "affected", value: "SurgeFTP version 2.3b6." );
	script_tag( name: "insight", value: "Input passed through the POST parameters 'fname', 'last',
  'class_name', 'filter', 'domainid', and 'classid' in '/cgi/surgeftpmgr.cgi' is not sanitized properly.
  Allowing the attacker to execute HTML code into admin's browser session." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running SurgeFTP Server and is prone to multiple
  reflected cross-site scripting vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "SurgeFTP" )){
	exit( 0 );
}
version = eregmatch( pattern: "SurgeFTP.*\\(Version ([^)]+)\\)", string: banner );
if(!isnull( version[1] )){
	if(version_is_equal( version: version[1], test_version: "2.3b6" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

