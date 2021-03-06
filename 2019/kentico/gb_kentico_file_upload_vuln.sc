CPE = "cpe:/a:kentico:cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142266" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-04-16 07:53:03 +0000 (Tue, 16 Apr 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-11 16:06:00 +0000 (Thu, 11 Apr 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-19453" );
	script_name( "Kentico < 11.0.45 File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kentico_cms_detect.sc" );
	script_mandatory_keys( "kentico_cms/detected" );
	script_tag( name: "summary", value: "Kentico CMS allows unrestricted upload of a file with a dangerous type." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It is possible for a malicious attacker to upload dangerous file types to
  perform attacks such as Cross-Site Scripting (XSS) and Cross-Origin Resource Sharing (CORS) attacks." );
	script_tag( name: "affected", value: "Kentico prior to version 11.0.45." );
	script_tag( name: "solution", value: "Update to version 11.0.45." );
	script_xref( name: "URL", value: "https://blog.hivint.com/advisory-upload-malicious-file-in-kentico-cms-cve-2018-19453-36debbf85216" );
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
path = infos["location"];
if(version_is_less( version: version, test_version: "11.0.45" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.0.45", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

