CPE = "cpe:/a:atlassian:crowd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106653" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-15 11:39:14 +0700 (Wed, 15 Mar 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_cve_id( "CVE-2017-5638" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Atlassian Crowd Struts2 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_crowd_detect.sc" );
	script_mandatory_keys( "atlassian_crowd/installed" );
	script_tag( name: "summary", value: "Atlassian Crowd is prone to a remote code execution vulnerability in
Struts2." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Crowd uses a version of Struts 2 that is vulnerable to CVE-2017-5638.
Attackers can use this vulnerability to execute Java code of their choice on the system." );
	script_tag( name: "affected", value: "Atlassiona Crowd 2.8.3 until 2.9.6, 2.10.1 until 2.10.2 and 2.11.0." );
	script_tag( name: "solution", value: "Update to version 2.9.7, 2.10.3, 2.11.1 or later." );
	script_xref( name: "URL", value: "https://jira.atlassian.com/browse/CWD-4879" );
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
if(version_in_range( version: version, test_version: "2.8.3", test_version2: "2.9.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.9.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.10.1", test_version2: "2.10.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.10.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "2.11.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.11.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

