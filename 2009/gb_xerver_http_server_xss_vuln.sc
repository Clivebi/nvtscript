if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801015" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-21 10:12:07 +0200 (Wed, 21 Oct 2009)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3562" );
	script_bugtraq_id( 36457 );
	script_name( "Xerver HTTP Server Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36681" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9718" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xerver_http_server_detect.sc" );
	script_require_ports( "Services/www", 32123, 80 );
	script_mandatory_keys( "xerver/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Xerver version 4.32 and prior on all platforms." );
	script_tag( name: "insight", value: "The flaw is due to improper sanitization of user supplied input
  passed via 'currentPath' parameter (when 'action' is set to 'chooseDirectory')
  to the administrative interface." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Xerver HTTP Server and is prone to Cross Site
  Scripting vulnerability" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
xerPort = http_get_port( default: 32123 );
xerVer = get_kb_item( "www/" + xerPort + "/Xerver" );
if(isnull( xerVer )){
	exit( 0 );
}
if(!safe_checks()){
	url = NASLString( "/action=chooseDirectory&currentPath=''>><script>alert('XSS-By-Stack')</script>" );
	request = http_get( item: url, port: xerPort );
	response = http_send_recv( port: xerPort, data: request );
	if(IsMatchRegexp( response, "^HTTP/1\\.[01] 200" ) && ContainsString( response, "XSS-By-Stack" )){
		report = http_report_vuln_url( port: xerPort, url: url );
		security_message( port: xerPort, data: report );
		exit( 0 );
	}
}
if(version_is_less_equal( version: xerVer, test_version: "4.32" )){
	security_message( xerPort );
}

