CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117600" );
	script_version( "2021-07-30T07:09:13+0000" );
	script_tag( name: "last_modification", value: "2021-07-30 07:09:13 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-30 06:28:42 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2014-0076" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL Information Disclosure Vulnerability (20140605 - 2) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Fix for the attack described in the paper 'Recovering OpenSSL
  ECDSA Nonces Using the FLUSH+RELOAD Cache Side-channel Attack'." );
	script_tag( name: "affected", value: "OpenSSL version 0.9.8 through 0.9.8y, 1.0.0 through 1.0.0l and
  1.0.1 through 1.0.1f." );
	script_tag( name: "solution", value: "Update to version 0.9.8za, 1.0.0m, 1.0.1g or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20140605.txt" );
	script_xref( name: "URL", value: "http://eprint.iacr.org/2014/140.pdf" );
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
if(version_in_range( version: version, test_version: "0.9.8", test_version2: "0.9.8y" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.8za", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.0", test_version2: "1.0.0l" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.0m", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1f" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1g", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

