CPE = "cpe:/a:op5:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106380" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-07 12:46:37 +0700 (Mon, 07 Nov 2016)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "op5 Remote Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_tuleap_detect.sc" );
	script_mandatory_keys( "OP5/installed" );
	script_tag( name: "summary", value: "op5 Monitor is prone to a remote command execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "op5 has a CSRF entry point that can be used to execute arbitrary remote
commands on op5 system sent via HTTP GET requests, allowing attackers to completely takeover the affected host,
to be victimized a user must be authenticated and visit a malicious webpage or click an infected link." );
	script_tag( name: "impact", value: "An authenticated attacker execute arbitrary commands." );
	script_tag( name: "affected", value: "op5 Monitor 7.1.19 and prior." );
	script_tag( name: "solution", value: "Update to 7.2.0 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39676/" );
	script_xref( name: "URL", value: "https://www.op5.com/blog/news/op5-monitor-7-2-0-release-notes/" );
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
if(version_is_less( version: version, test_version: "7.2.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

