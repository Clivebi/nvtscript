CPE = "cpe:/o:aerohive:hiveos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106876" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-06-16 12:18:01 +0700 (Fri, 16 Jun 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Aerohive Networks HiveOS Remote Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_aerohive_hiveos_detect.sc" );
	script_mandatory_keys( "aerohive_hiveos/detected" );
	script_tag( name: "summary", value: "Aerohive HiveOS is prone to a remote command execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "With a local file inclusion it is possible to poison /var/log/messages
with PHP code which allows an attacker to e.g. change the root password." );
	script_tag( name: "affected", value: "HiveOS 5.1r5 until 6.1r4." );
	script_tag( name: "solution", value: "Update to version 6.1r5 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42178/" );
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
if(version_in_range( version: version, test_version: "5.1r5", test_version2: "6.1r4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1r5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

