if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103653" );
	script_bugtraq_id( 57579 );
	script_cve_id( "CVE-2013-1391" );
	script_version( "2021-07-01T11:00:40+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Multiple DVR Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57579" );
	script_xref( name: "URL", value: "http://www.securitybydefault.com/2013/01/12000-grabadores-de-video-expuestos-en.html" );
	script_tag( name: "last_modification", value: "2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-05 16:33:00 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2013-02-01 10:51:23 +0100 (Fri, 01 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Multiple DVR devices are prone to a remote information-
disclosure vulnerability.

Successful exploits will allow attackers to obtain sensitive
information, such as credentials, that may aid in further attacks
from '/DVR.cfg'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/DVR.cfg";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "WEB_ADMIN_ID" ) && ContainsString( buf, "WEB_ADMIN_PWD" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

