CPE = "cpe:/a:phpliteadmin_project:phpliteadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106117" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-05 12:29:33 +0700 (Tue, 05 Jul 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpLiteAdmin PHP Code Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpliteadmin_detect.sc" );
	script_mandatory_keys( "phpliteadmin/installed" );
	script_tag( name: "summary", value: "phpLiteAdmin is prone to a PHP code injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An authenticated attacker can create a sqlite Database with a php
extension and insert PHP Code as text fields. When done the attacker can execute it simply by access the
database file with the Webbrowser." );
	script_tag( name: "impact", value: "An attacker may execute arbitrary PHP code." );
	script_tag( name: "affected", value: "Version <= 1.9.3" );
	script_tag( name: "solution", value: "Update to 1.9.4 or newer." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/24044/" );
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
if(version_is_less( version: version, test_version: "1.9.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.9.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

