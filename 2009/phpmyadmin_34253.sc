CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100078" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-03-26 13:41:22 +0100 (Thu, 26 Mar 2009)" );
	script_bugtraq_id( 34253 );
	script_cve_id( "CVE-2009-1148", "CVE-2009-1149" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpMyAdmin BLOB Streaming Multiple Input Validation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34253" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to multiple input-validation vulnerabilities,
  including an HTTP response-splitting vulnerability and a local file-include vulnerability." );
	script_tag( name: "impact", value: "These issues can be leveraged to view or execute arbitrary local
  scripts, or misrepresent how web content is served, cached, or interpreted. This could aid in
  various attacks that try to entice client users into a false sense of trust. Other attacks are also
  possible." );
	script_tag( name: "affected", value: "Versions prior to phpMyAdmin 3.1.3.1 are vulnerable." );
	script_tag( name: "solution", value: "Update to version 3.1.3.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "3.1.3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.3.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

