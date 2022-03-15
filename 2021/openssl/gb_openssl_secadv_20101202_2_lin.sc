CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112950" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-16 10:54:11 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4252" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: JPAKE validation error (20101202) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to a JPAKE validation error." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error in OpenSSL's experimental J-PAKE implementation could
  lead to successful validation by someone with no knowledge of the shared secret." );
	script_tag( name: "affected", value: "OpenSSL 1.0.0 through 1.0.0b." );
	script_tag( name: "solution", value: "Update to version 1.0.0c or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20101202.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "1.0.0", test_version2: "1.0.0b" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.0c", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

