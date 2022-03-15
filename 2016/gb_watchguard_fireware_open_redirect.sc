CPE = "cpe:/o:watchguard:fireware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106080" );
	script_version( "2020-11-12T10:09:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-05-20 11:08:44 +0700 (Fri, 20 May 2016)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WatchGuard Fireware XTM Web UI Open Redirect Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_snmp_os_detection.sc", "gb_watchguard_fireware_detect.sc" );
	script_mandatory_keys( "watchguard_fireware/installed" );
	script_tag( name: "summary", value: "WatchGuard Fireware XMT Web UI is prone to an open redirect
vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An open redirect vulnerability has been detected in the login form." );
	script_tag( name: "impact", value: "A remote user can create a URL that, when loaded by the target user,
will exploit an input validation flaw in the management Web UI authentication form and redirect the target
user's browser to an arbitrary site." );
	script_tag( name: "affected", value: "Version prior to 11.10.7." );
	script_tag( name: "solution", value: "Upgrade to version 11.10.7 or later" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Apr/22" );
	script_xref( name: "URL", value: "https://www.watchguard.com/support/release-notes/fireware/11/en-US/#Fireware/en-US/resolved_issues.html?TocPath=_____11" );
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
if(version_is_less( version: version, test_version: "11.10.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.10.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

