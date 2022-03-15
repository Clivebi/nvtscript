if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113739" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-08-11 06:47:23 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-13 15:58:00 +0000 (Thu, 13 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-17447", "CVE-2020-15139" );
	script_name( "MyBB < 1.8.24 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_mybb_detect.sc" );
	script_mandatory_keys( "MyBB/installed" );
	script_tag( name: "summary", value: "MyBB is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because the visual editor
  mishandles 'align', 'size', 'quote' and 'font' in MyCode." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "MyBB through version 1.8.23." );
	script_tag( name: "solution", value: "Update to version 1.8.24 or later." );
	script_xref( name: "URL", value: "https://blog.mybb.com/2020/08/09/mybb-1-8-24-released-security-release/" );
	script_xref( name: "URL", value: "https://github.com/mybb/mybb/security/advisories/GHSA-37h7-vfv6-f8rj" );
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
if(version_is_less( version: version, test_version: "1.8.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.24", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

