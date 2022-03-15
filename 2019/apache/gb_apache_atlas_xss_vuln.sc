CPE = "cpe:/a:apache:atlas";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143175" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-26 03:35:41 +0000 (Tue, 26 Nov 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-19 20:35:00 +0000 (Tue, 19 Nov 2019)" );
	script_cve_id( "CVE-2019-10070" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Atlas XSS Vulnerability - Nov19" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_atlas_detect.sc" );
	script_mandatory_keys( "Apache/Atlas/Installed" );
	script_tag( name: "summary", value: "Apache Atlas is prone to a stored cross-site scripting vulnerability in the
  search functionality." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache Atlas versions 0.8.3 and 1.1.0." );
	script_tag( name: "solution", value: "Upgrade to Version 0.8.4, 1.2.0 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/cc21437c4c5053a13e13332d614d5172f39da03491fe17ae260be221@%3Cdev.atlas.apache.org%3E" );
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
if(version_is_equal( version: version, test_version: "0.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.8.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "1.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

