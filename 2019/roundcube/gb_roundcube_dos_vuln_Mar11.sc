CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114122" );
	script_version( "2019-09-04T12:20:04+0000" );
	script_tag( name: "last_modification", value: "2019-09-04 12:20:04 +0000 (Wed, 04 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-08-21 13:38:15 +0200 (Wed, 21 Aug 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-4078" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail <= 0.5.4 Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to a denial of service vulnerability." );
	script_tag( name: "insight", value: "The file 'include/iniset.php', when PHP 5.3.7 or 5.3.8 is used,
  allows remote attackers to trigger a GET request for an arbitrary URL and cause a denial of
  service (resource consumption and inbox outage), via a Subject header containing only a URL." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions 0.5.4 and prior." );
	script_tag( name: "solution", value: "Update to version 0.6, or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/3505" );
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
if(version_is_less_equal( version: version, test_version: "0.5.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

