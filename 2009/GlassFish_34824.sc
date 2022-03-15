CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100191" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1553" );
	script_bugtraq_id( 34824 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "GlassFish Enterprise Server Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	script_require_ports( "Services/www", 8080 );
	script_xref( name: "URL", value: "https://glassfish.dev.java.net/" );
	script_xref( name: "URL", value: "http://www.sun.com/software/products/appsrvr/index.xml" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34824" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "GlassFish Enterprise Server is prone to multiple cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Attacker-supplied HTML and script code would run in the context of the affected site, potentially allowing the
  attacker to steal cookie-based authentication credentials." );
	script_tag( name: "affected", value: "GlassFish Enterprise Server 2.1 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

