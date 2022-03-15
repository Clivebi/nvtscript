CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813324" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2017-0936" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-05-02 18:06:32 +0530 (Wed, 02 May 2018)" );
	script_name( "Nextcloud Server Authorization Bypass Vulnerability May18 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Nextcloud Server
  and is prone to authorization bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a missing ownership
  check while changing the scope of app passwords of other users." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to change the scope of app passwords of other users. Note that the app passwords
  themselves where neither disclosed nor could the error be misused to identify as
  another user." );
	script_tag( name: "affected", value: "Nextcloud Server before 11.0.7 and 12.0.5." );
	script_tag( name: "solution", value: "Upgrade to version 11.0.7 or 12.0.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2018-001" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "nextcloud/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_is_less( version: vers, test_version: "11.0.7" ) ){
	fix = "11.0.7";
}
else {
	if(version_in_range( version: vers, test_version: "12.0", test_version2: "12.0.4" )){
		fix = "12.0.5";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

