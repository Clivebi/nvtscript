CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112978" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-17 06:07:11 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-30 21:30:00 +0000 (Fri, 30 Nov 2018)" );
	script_cve_id( "CVE-2015-1793" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Alternative Chains Certificate Forgery (20150709) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to certificate forgery." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error in the implementation of the alternative certificate
  chain logic could allow an attacker to cause certain checks on untrusted certificates to be
  bypassed, such as the CA flag, enabling them to use a valid leaf certificate to act as a CA
  and 'issue' an invalid certificate." );
	script_tag( name: "affected", value: "OpenSSL 1.0.1n through 1.0.1o and 1.0.2b through 1.0.2c." );
	script_tag( name: "solution", value: "Update to version 1.0.1p, 1.0.2d or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20150709.txt" );
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
if(version_in_range( version: version, test_version: "1.0.1n", test_version2: "1.0.1o" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1p", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.0.2b", test_version2: "1.0.2c" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.2d", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

