if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113509" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-11 12:40:40 +0000 (Wed, 11 Sep 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-30 19:15:00 +0000 (Wed, 30 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15780" );
	script_name( "WordPress Formidable Forms Builder Plugin < 4.02.01 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/formidable/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Formidable Forms Builder is prone to
  a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists due to unsafe deserialization." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  execute arbitrary code on the target machine." );
	script_tag( name: "affected", value: "WordPress Formidable Forms Builder through version 4.02." );
	script_tag( name: "solution", value: "Update to version 4.02.01 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/formidable/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:strategy11:formidable";
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
if(version_is_less( version: version, test_version: "4.02.01" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.02.01", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

