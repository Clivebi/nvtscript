CPE = "cpe:/a:hp:sitescope";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805285" );
	script_version( "2019-12-18T15:04:04+0000" );
	script_cve_id( "CVE-2014-2614", "CVE-2014-7882" );
	script_bugtraq_id( 72459, 68361 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-02-23 11:23:51 +0530 (Mon, 23 Feb 2015)" );
	script_name( "HP SiteScope Multiple Unspecified Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hp_sitescope_detect.sc" );
	script_mandatory_keys( "hp/sitescope/installed" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "summary", value: "This host is installed with HP SiteScope
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified errors exists" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass authentication and gain elevated privileges." );
	script_tag( name: "affected", value: "HP SiteScope 11.1x through 11.13 and
  11.2x through 11.24" );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: http_port, exit_no_version: TRUE )){
	exit( 0 );
}
hpVer = infos["version"];
location = infos["location"];
if(version_in_range( version: hpVer, test_version: "11.10", test_version2: "11.13" )){
	fix = "SiS 11.13 Patch";
	VULN = TRUE;
}
if(version_in_range( version: hpVer, test_version: "11.20", test_version2: "11.24" )){
	fix = "SiS 11.24 Patch";
	VULN = TRUE;
}
if(VULN){
	report = report_fixed_ver( installed_version: hpVer, fixed_version: fix, install_path: location );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

