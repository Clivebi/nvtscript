if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900496" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1275" );
	script_bugtraq_id( 34657 );
	script_name( "Apache Tiles Multiple XSS Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_apache_tiles_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/tiles/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker access the server context
  inside the tiles web application and perform XSS attacks." );
	script_tag( name: "affected", value: "Apache Tiles version 2.1 to 2.1.1." );
	script_tag( name: "insight", value: "This flaw is due to attribute values or templates being defined by using
  JSP tags 'tiles:putAttribute', 'tiles:insertTemplate' which are being evaluated twice." );
	script_tag( name: "solution", value: "Upgrade your Apache Tiles version to 2.1.2." );
	script_tag( name: "summary", value: "This host has Apache Tiles installed and is prone to multiple Cross-Site
  Scripting Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://issues.apache.org/struts/browse/TILES-351" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc/tiles/framework/trunk/src/site/apt/security/security-bulletin-1.apt?revision=741913" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
tilesPort = http_get_port( default: 8080 );
version = get_kb_item( "www/" + tilesPort + "/Apache/Tiles" );
version = eregmatch( pattern: "^(.+) under (/.*)$", string: version );
if(version[1] == NULL){
	exit( 0 );
}
if(version_in_range( version: version[1], test_version: "2.1", test_version2: "2.1.1" )){
	report = report_fixed_ver( installed_version: version[1], vulnerable_range: "2.1 - 2.1.1" );
	security_message( port: tilesPort, data: report );
	exit( 0 );
}
exit( 99 );

