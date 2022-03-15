CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144867" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-30 04:04:16 +0000 (Fri, 30 Oct 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-17 19:14:00 +0000 (Tue, 17 Nov 2020)" );
	script_cve_id( "CVE-2020-8173" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nextcloud Server < 17.0.7, 18.x < 18.0.5 Cryptographic Vulnerability (NC-SA-2020-023)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc" );
	script_mandatory_keys( "nextcloud/installed" );
	script_tag( name: "summary", value: "Nextcloud Server is prone to a cryptographic vulnerability." );
	script_tag( name: "insight", value: "A too small set of random characters being used for encryption in Nextcloud
  Server allows decryption in shorter time than intended." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Nextcloud server versions prior 17.0.7 and 18.0.0 - 18.0.4." );
	script_tag( name: "solution", value: "Update to version 17.0.7, 18.0.5 or later." );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=NC-SA-2020-023" );
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
if(version_is_less( version: version, test_version: "17.0.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.0.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "18.0.0", test_version2: "18.0.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.0.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

