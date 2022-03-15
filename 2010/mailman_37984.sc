CPE = "cpe:/a:gnu:mailman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100475" );
	script_version( "$Revision: 11723 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-02 11:59:19 +0200 (Tue, 02 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)" );
	script_bugtraq_id( 37984 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "GNU Mailman Unspecified Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "mailman_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "gnu_mailman/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37984" );
	script_xref( name: "URL", value: "http://mailman.sourceforge.net/index.html" );
	script_tag( name: "summary", value: "Mailman is prone to an unspecified privilege-escalation scripting
  vulnerability." );
	script_tag( name: "insight", value: "Few technical details are available at this time." );
	script_tag( name: "impact", value: "Local attackers may exploit this issue to obtain elevated privileges
  and compromise a computer." );
	script_tag( name: "affected", value: "This issue is known to affect Mailman 2.0.2 and 2.0.4, other versions
  may be vulnerable as well." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!info = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = info["version"];
path = info["location"];
if(version_is_equal( version: vers, test_version: "2.0.2" ) || version_is_equal( version: vers, test_version: "2.0.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

