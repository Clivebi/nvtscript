CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103673" );
	script_bugtraq_id( 57746 );
	script_cve_id( "CVE-2013-1453" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "Joomla! 'highlight' Parameter PHP Object Injection Vulnerability" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2013-03-03 10:29:04 +0100 (Sun, 03 Mar 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57746" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "Joomla! is prone to a remote PHP object-injection vulnerability because it
  fails to properly validate user-supplied input." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to inject arbitrary object in to the application.
  This may aid in further attacks." );
	script_tag( name: "affected", value: "Joomla! 2.0.0 through versions prior to 2.5.9

  Joomla! 3.0.0 through versions prior to 3.0.3" );
	script_tag( name: "qod", value: "50" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?highlight=YToxOntpOjA7Tzo3OiJPcGVuVkFTIjowOnt9fQ==";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "HTTP/1.. 500" ) || ContainsString( buf, "Catchable fatal error: Object of class __PHP_Incomplete_Class could not be converted to string" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

