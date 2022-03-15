CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112927" );
	script_version( "2021-08-30T10:29:27+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:29:27 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 07:06:11 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2004-0975" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL: Insecure Temporary File Creation (CVE-2004-0975) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "OpenSSL is prone to an insecure temporary file creation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The der_chop script created temporary files insecurely which
  could allow local users to overwrite files via a symlink attack on temporary files. Note that it
  is quite unlikely that a user would be using the redundant der_chop script, and this script was
  removed from the OpenSSL distribution." );
	script_tag( name: "affected", value: "OpenSSL 0.9.6 through 0.9.6m and 0.9.7 through 0.9.7e." );
	script_tag( name: "solution", value: "Update to version 0.9.7f or later." );
	script_xref( name: "URL", value: "https://github.com/openssl/openssl/commit/5fee606442a6738fd06a756d7076be53b7b7734c" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/vulnerabilities.html#y2004" );
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
if(version_in_range( version: version, test_version: "0.9.6", test_version2: "0.9.7e" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.9.7f", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

