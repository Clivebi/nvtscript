CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807098" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-0705", "CVE-2016-0798", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-0702", "CVE-2016-2842" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-03 12:23:09 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OpenSSL Multiple Vulnerabilities -01 Mar16 (Linux)" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A double-free vulnerability in DSA code.

  - A memory leak vulnerability in SRP database lookups using the
    'SRP_VBASE_get_by_user' function.

  - An integer overflow flaw in some 'BIGNUM' functions, leading to a NULL
    pointer dereference or a heap-based memory corruption.

  - An improper processing of format string in the 'BIO_*printf' functions.

  - A side channel attack on modular exponentiation.

  - The 'doapr_outch' function in 'crypto/bio/b_print.c' script does not verify
    the success of a certain memory allocation" );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause denial of service, to cause memory leak, to execute
  arbitrary code and to bypass seurity restrictions and some unspecified other
  impact." );
	script_tag( name: "affected", value: "OpenSSL versions 1.0.1 before 1.0.1s
  and 1.0.2 before 1.0.2g." );
	script_tag( name: "solution", value: "Upgrade to OpenSSL 1.0.1s or 1.0.2g or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20160301.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
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
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^1\\.0\\.1" ) ){
	if(version_is_less( version: vers, test_version: "1.0.1s" )){
		fix = "1.0.1s";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( vers, "^1\\.0\\.2" )){
		if(version_is_less( version: vers, test_version: "1.0.2g" )){
			fix = "1.0.2g";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

