if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100234" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-20 17:00:58 +0200 (Mon, 20 Jul 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-6132" );
	script_bugtraq_id( 31520 );
	script_name( "phpScheduleIt 'reserve.php' Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/31520" );
	script_xref( name: "URL", value: "http://www.php.brickhost.com/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phpScheduleIt_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpscheduleit/detected" );
	script_tag( name: "summary", value: "phpScheduleIt is prone to a vulnerability that lets remote attackers
  execute arbitrary code because the application fails to sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can leverage this issue to execute arbitrary PHP code on
  an affected computer with the privileges of the webserver process." );
	script_tag( name: "affected", value: "phpScheduleIt 1.2.10 is vulnerable, other versions may also be
  affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/phpScheduleIt" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_less_equal( version: vers, test_version: "1.2.10" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

