if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100348" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-11-16 11:47:06 +0100 (Mon, 16 Nov 2009)" );
	script_cve_id( "CVE-2009-4040" );
	script_bugtraq_id( 37020 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "phpMyFAQ Search Page Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37020" );
	script_xref( name: "URL", value: "http://www.phpmyfaq.de/advisory_2009-09-01.php" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phpmyfaq_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpmyfaq/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "phpMyFAQ is prone to a cross-site scripting vulnerability because the
  application fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to phpMyFAQ 2.5.2 and 2.0.17 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/phpmyfaq" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_in_range( version: vers, test_version: "2.5", test_version2: "2.5.1" ) || version_in_range( version: vers, test_version: "2.0", test_version2: "2.0.16" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

