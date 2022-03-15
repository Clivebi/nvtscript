CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145407" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-17 06:15:32 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2021-23840" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Integer overflow in CipherUpdate (CVE-2021-23840) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to an integer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may
  overflow the output length argument in some cases where the input length is close to the maximum permissible
  length for an integer on the platform. In such cases the return value from the function call will be 1
  (indicating success), but the output length value will be negative." );
	script_tag( name: "impact", value: "This vulnerability could cause applications to behave incorrectly or crash." );
	script_tag( name: "affected", value: "OpenSSL versions 1.0.2x and prior and 1.1.1i and prior." );
	script_tag( name: "solution", value: "Update to version 1.0.2y, 1.1.1j or later. See the references for
  more details." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20210216.txt" );
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
if(version_is_less( version: version, test_version: "1.0.2y" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.2y / 1.1.1j", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.1.0", test_version2: "1.1.1i" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.1j", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

