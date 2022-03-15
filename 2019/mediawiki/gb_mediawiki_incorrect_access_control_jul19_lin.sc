if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113438" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-16 11:06:09 +0000 (Tue, 16 Jul 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-12472" );
	script_name( "MediaWiki >= 1.18.0, <= 1.32.1 Incorrect Access Control (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_mediawiki_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mediawiki/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MediaWiki is prone to incorrect access control" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It is possible to bypass the limits on IP range blocks ($wgBlockCIDRLimit)
  by using the API." );
	script_tag( name: "impact", value: "Successful exploitation would allow a user
  from a blocked IP to access and edit the Wiki anyway." );
	script_tag( name: "affected", value: "MediaWiki versions 1.18.0 through 1.27.5, 1.28.0 through 1.30.1,
  1.31.0 through 1.31.1 and 1.32.0 through 1.32.1." );
	script_tag( name: "solution", value: "Update to version 1.27.6, 1.30.2, 1.31.2 or 1.32.2 respectively." );
	script_xref( name: "URL", value: "https://lists.wikimedia.org/pipermail/wikitech-l/2019-June/092152.html" );
	script_xref( name: "URL", value: "https://phabricator.wikimedia.org/T199540" );
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
if(version_in_range( version: version, test_version: "1.18.0", test_version2: "1.27.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.27.6", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.28.0", test_version2: "1.30.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.30.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.31.0", test_version2: "1.31.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.31.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.32.0", test_version2: "1.32.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.32.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

