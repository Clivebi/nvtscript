CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145600" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-22 05:11:48 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-25097" );
	script_name( "Squid 2.0 < 4.14, 5.0.1 < 5.0.5 HTTP Request Smuggling Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to an HTTP request smuggling vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to improper input validation, it allows a trusted client to perform
  HTTP Request Smuggling and access services otherwise forbidden by the security controls. This occurs for
  certain uri_whitespace configuration settings." );
	script_tag( name: "affected", value: "Squid version 2.0 through 4.13 and 5.0.1 through 5.0.4." );
	script_tag( name: "solution", value: "Update to version 4.13, 5.0.5 or later. See the referenced vendor
  advisory for a workaround." );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/security/advisories/GHSA-jvf6-h9gj-pmj6" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "2.0", test_version2: "4.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.14", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.1", test_version2: "5.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

