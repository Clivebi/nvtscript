CPE = "cpe:/a:adobe:coldfusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112084" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-12 12:22:43 +0200 (Wed, 12 Jun 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 14:21:00 +0000 (Fri, 04 Sep 2020)" );
	script_cve_id( "CVE-2019-7838", "CVE-2019-7840" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Adobe ColdFusion Multiple Vulnerabilities (APSB19-27)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_coldfusion_detect.sc" );
	script_mandatory_keys( "adobe/coldfusion/detected" );
	script_tag( name: "summary", value: "Adobe ColdFusion is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - File extension blacklist bypass (CVE-2019-7838)

  - Deserialization of untrusted data (CVE-2019-7840)" );
	script_tag( name: "impact", value: "Successful exploitation could lead to arbitrary code execution." );
	script_tag( name: "affected", value: "Adobe ColdFusion version 11 prior to Update 19, version 2016 prior to Update 11 and version 2018 prior to Update 4." );
	script_tag( name: "solution", value: "Update to version 11 Update 19, version 2016 Update 11 or version 2018 Update 4 respectively." );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/coldfusion/apsb19-27.html" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/coldfusion/kb/coldfusion-11-update-19.html" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/coldfusion/kb/coldfusion-2016-update-11.html" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/coldfusion/kb/coldfusion-2018-update-4.html" );
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
path = infos["location"];
if(IsMatchRegexp( version, "^11\\.0" ) && version_is_less( version: version, test_version: "11.0.19.314545" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.0.19.314546", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2016\\.0" ) && version_is_less( version: version, test_version: "2016.0.11.314545" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2016.0.11.314546", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2018\\.0" ) && version_is_less( version: version, test_version: "2018.0.04.314545" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2018.0.04.314546", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

