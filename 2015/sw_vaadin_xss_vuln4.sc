CPE = "cpe:/a:vaadin:vaadin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105185" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Vaadin Framework Portlet Error Messages Cross-Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_vaadin_detect.sc" );
	script_require_ports( "Services/www", 8888 );
	script_mandatory_keys( "vaadin/installed" );
	script_tag( name: "summary", value: "This web application is running with the Vaadin Framework which
  is prone to cross-site scripting because the application fails to properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This flaw exists due to proper escaping of HTML in portlet error
  message was not ensured." );
	script_tag( name: "impact", value: "This could allow a reflected cross-site scripting attack through
  VaadinPortlet by making the user load a URL designed to include an error message crafted by the attacker." );
	script_tag( name: "affected", value: "Vaadin Framework versions from 7.0.0 up to 7.3.6" );
	script_tag( name: "solution", value: "Upgrade to Vaadin Framework version 7.3.7 or later." );
	script_xref( name: "URL", value: "http://www.vaadin.com/download/release/7.3/7.3.7/release-notes.html" );
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
if(version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.3.6" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + "7.3.7" + "\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

