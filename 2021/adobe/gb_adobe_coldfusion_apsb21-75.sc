CPE = "cpe:/a:adobe:coldfusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818534" );
	script_version( "2021-09-24T05:06:20+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 05:06:20 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-16 13:01:06 +0530 (Thu, 16 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2021-40699", "CVE-2021-40698" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Adobe ColdFusion Multiple Vulnerabilities (APSB21-75)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_coldfusion_detect.sc" );
	script_mandatory_keys( "adobe/coldfusion/detected" );
	script_tag( name: "summary", value: "Adobe ColdFusion is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation allow attackers to bypass
  security and launch further attacks." );
	script_tag( name: "affected", value: "- Adobe ColdFusion 2018 Update 11 and earlier versions.

  - Adobe ColdFusion 2021 Version 1 and earlier versions." );
	script_tag( name: "solution", value: "Update to version 2018 Update 12, 2021 Update 2 or later." );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/coldfusion/apsb21-75.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(IsMatchRegexp( version, "^2021\\.0" ) && version_is_less( version: version, test_version: "2021.0.02.328618" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2021.0.02.328618", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2018\\.0" ) && version_is_less( version: version, test_version: "2018.0.12.328566" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2018.0.12.328566", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

