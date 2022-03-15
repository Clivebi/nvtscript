CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146732" );
	script_version( "2021-09-22T07:15:16+0000" );
	script_tag( name: "last_modification", value: "2021-09-22 07:15:16 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-21 08:55:16 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-4394", "CVE-2012-4753" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ownCloud < 4.0.5 Multiple Vulnerabilities (oC-SA-2012-018)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_tag( name: "summary", value: "ownCloud is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2012-4394: Cross-site scripting (XSS) in  apps/files/js/filelist.js

  - CVE-2012-4753: Multiple cross-site request forgery (CSRF)" );
	script_tag( name: "affected", value: "ownCloud prior to version 4.0.5." );
	script_tag( name: "solution", value: "Update to version 4.0.5 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2012/09/02/2" );
	script_xref( name: "URL", value: "https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2012-018.json" );
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
if(version_is_less( version: version, test_version: "4.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

