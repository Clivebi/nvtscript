CPE = "cpe:/a:mediawiki:mediawiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143273" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-12-18 08:48:51 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-28 18:15:00 +0000 (Sat, 28 Dec 2019)" );
	script_cve_id( "CVE-2019-19709" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MediaWiki < 1.31.6 / 1.32.6 / 1.33.2 / 1.34.0 Blacklist Bypass Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mediawiki/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MediaWiki is prone to a blacklist bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "MediaWiki allows attackers to bypass the Title_blacklist
  protection mechanism by starting with an arbitrary title, establishing a non-resolvable
  redirect for the associated page, and using redirect=1 in the action API when editing
  that page." );
	script_tag( name: "affected", value: "MediaWiki prior to version 1.31.6, 1.32.6, 1.33.2 and
  1.34.0." );
	script_tag( name: "solution", value: "Update MediaWiki to version 1.31.6, 1.32.6, 1.33.2,
  1.34.0 or later." );
	script_xref( name: "URL", value: "https://phabricator.wikimedia.org/T239466" );
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
if( version_is_less( version: version, test_version: "1.31.6" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.31.6 / 1.32.6 / 1.33.2 / 1.34.0", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
else {
	if( IsMatchRegexp( version, "^1\\.32" ) && version_is_less( version: version, test_version: "1.32.6" ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.32.6 / 1.33.2 / 1.34.0", install_path: location );
		security_message( data: report, port: port );
		exit( 0 );
	}
	else {
		if(IsMatchRegexp( version, "^1\\.33" ) && version_is_less( version: version, test_version: "1.33.2" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "1.33.2 / 1.34.0", install_path: location );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

