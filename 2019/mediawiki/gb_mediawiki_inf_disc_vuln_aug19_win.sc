if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112643" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-30 13:15:44 +0000 (Mon, 30 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-18 19:15:00 +0000 (Fri, 18 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-16738" );
	script_name( "MediaWiki <= 1.33.0 Information Disclosure Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mediawiki/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "MediaWiki is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Special:Redirect allows information disclosure of suppressed usernames via a User ID Lookup." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to read sensitive information." );
	script_tag( name: "affected", value: "MediaWiki versions through 1.33.0." );
	script_tag( name: "solution", value: "Update to version 1.34.0 or later." );
	script_xref( name: "URL", value: "https://phabricator.wikimedia.org/T230402" );
	exit( 0 );
}
CPE = "cpe:/a:mediawiki:mediawiki";
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
if(version_is_less( version: version, test_version: "1.34.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.34.0", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

