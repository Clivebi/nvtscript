CPE = "cpe:/a:peersec_networks:matrixssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112605" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-07-11 14:57:00 +0200 (Thu, 11 Jul 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-16 13:36:00 +0000 (Tue, 16 Jul 2019)" );
	script_cve_id( "CVE-2019-13470" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MatrixSSL 4.2.1 Out-Of-Bounds Read Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_matrixssl_detect.sc" );
	script_mandatory_keys( "matrixssl/installed" );
	script_tag( name: "summary", value: "MatrixSSL is prone to an out-of-bounds read vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in ASN.1 handling." );
	script_tag( name: "affected", value: "MatrixSSL before version 4.2.1." );
	script_tag( name: "solution", value: "Update to version 4.2.1 or later." );
	script_xref( name: "URL", value: "https://github.com/matrixssl/matrixssl/blob/4-2-1-open/doc/CHANGES_v4.x.md#changes-between-420-and-421-june-2019" );
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
if(version_is_less( version: version, test_version: "4.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

