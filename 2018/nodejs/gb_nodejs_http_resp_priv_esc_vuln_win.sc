CPE = "cpe:/a:nodejs:node.js";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814521" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-12116" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 21:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-11-29 13:44:53 +0530 (Thu, 29 Nov 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Node.js 'HTTP Splitting' Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Node.js and is
  prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in due to an error in HTTP
  request splitting. If Node.js can be convinced to use unsanitized user-provided
  Unicode data for the `path` option of an HTTP request, then data can be
  provided which will trigger a second, unexpected, and user-defined HTTP
  request to made to the same server." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct spoofing attacks." );
	script_tag( name: "affected", value: "Node.js all versions prior to 6.15.0
  and 8.14.0 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Node.js version 6.15.0, 8.14.0
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://nodejs.org/en/blog/vulnerability/november-2018-security-releases" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_nodejs_detect_win.sc" );
	script_mandatory_keys( "Nodejs/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
nodejsVer = infos["version"];
appPath = infos["location"];
if( version_in_range( version: nodejsVer, test_version: "6.0", test_version2: "6.14.0" ) ){
	fix = "6.15.0";
}
else {
	if(version_in_range( version: nodejsVer, test_version: "8.0", test_version2: "8.13.0," )){
		fix = "8.14.0";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: nodejsVer, fixed_version: fix, install_path: appPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

