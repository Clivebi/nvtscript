if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113790" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-23 10:45:17 +0000 (Tue, 23 Feb 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-26 15:37:00 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2021-27279" );
	script_name( "MyBB < 1.8.25 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "summary", value: "MyBB is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is exploitabl via nested [email] tags with BBCode." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  inject arbitrary JavaScript and HTML into the site." );
	script_tag( name: "affected", value: "MyBB through version 1.8.24." );
	script_tag( name: "solution", value: "Update to version 1.8.25 or later." );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-6483-hcpp-p75w" );
	exit( 0 );
}
CPE = "cpe:/a:mybb:mybb";
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
if(version_is_less( version: version, test_version: "1.8.25" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.25", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

