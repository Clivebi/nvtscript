CPE = "cpe:/a:logpoint:logpoint";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106867" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-06-13 13:29:03 +0700 (Tue, 13 Jun 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "LogPoint Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_logpoint_detect.sc" );
	script_mandatory_keys( "logpoint/detected" );
	script_tag( name: "summary", value: "LogPoint is prone to an unauthenticated remote command execution
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "A unauthenticated attacker may execute arbitrary commands as root." );
	script_tag( name: "affected", value: "LogPoint prior to version 5.6.4." );
	script_tag( name: "solution", value: "Update to version 5.6.4 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42158/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.6.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

