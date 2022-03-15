if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113473" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 13:08:04 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 17:53:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2016-10880" );
	script_name( "WordPress Google Doc Embedder Plugin < 2.6.1 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wordpress_plugin_http_detect.sc" );
	script_mandatory_keys( "wordpress/plugin/google-document-embedder/detected" );
	script_tag( name: "summary", value: "The WordPress plugin Google Doc Embedder is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "WordPress Google Doc Embedder plugin through version 2.6.0." );
	script_tag( name: "solution", value: "Update to version 2.6.1 or later." );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/google-document-embedder/#developers" );
	exit( 0 );
}
CPE = "cpe:/a:kevin_davis:google-document-embedder";
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
if(version_is_less( version: version, test_version: "2.6.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.6.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

