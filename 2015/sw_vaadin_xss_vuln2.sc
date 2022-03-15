CPE = "cpe:/a:vaadin:vaadin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105183" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Vaadin Framework src-attribute Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_vaadin_detect.sc" );
	script_require_ports( "Services/www", 8888 );
	script_mandatory_keys( "vaadin/installed" );
	script_tag( name: "summary", value: "This web application is running with the Vaadin Framework which
  is prone to cross-site scripting because the application fails to properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Proper escaping of the src-attribute on the client side was not ensured
  when using icons for OptionGroup items." );
	script_tag( name: "impact", value: "This could potentially, in certain situations, allow a malicious user
  to inject content, such as javascript, in order to perform a cross-site scripting (XSS) attack." );
	script_tag( name: "affected", value: "Vaadin Framework versions from 6.0.0 up to 6.8.13" );
	script_tag( name: "solution", value: "Upgrade to Vaadin Framework version 6.8.14 or later." );
	script_xref( name: "URL", value: "http://www.vaadin.com/download/release/6.8/6.8.14/release-notes.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.vaadin.com/releases" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.8.13" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "6.8.14" + "\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

