CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146734" );
	script_version( "2021-09-21T11:22:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-21 11:22:28 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-21 09:02:22 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-4396" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ownCloud < 4.0.2 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_tag( name: "summary", value: "ownCloud is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple cross-site scripting (XSS) vulnerabilities allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "ownCloud prior to version 4.0.2." );
	script_tag( name: "solution", value: "Update to version 4.0.2 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2012/09/02/2" );
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
if(version_is_less( version: version, test_version: "4.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

