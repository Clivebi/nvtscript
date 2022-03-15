CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807816" );
	script_version( "2021-03-10T13:27:48+0000" );
	script_cve_id( "CVE-2016-2108" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-03-10 13:27:48 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-05-10 17:58:27 +0530 (Tue, 10 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenSSL Multiple Vulnerabilities-02 May16 (Windows)" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the ASN.1 parser
  (specifically, d2i_ASN1_TYPE) can misinterpret a large universal tag as a negative
  zero value and if an application deserializes untrusted ASN.1 structures
  containing an ANY field, and later reserializes them, it can trigger an
  out-of-bounds write." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to execute arbitrary code or cause a denial of service (buffer underflow
  and memory corruption) condition." );
	script_tag( name: "affected", value: "OpenSSL versions 1.0.1 before 1.0.1o
  and 1.0.2 before 1.0.2c." );
	script_tag( name: "solution", value: "Upgrade to OpenSSL 1.0.1o or 1.0.2c or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20160503.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
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
	if(version_is_less( version: vers, test_version: "1.0.1o" )){
		fix = "1.0.1o";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( vers, "^1\\.0\\.2" )){
		if(version_is_less( version: vers, test_version: "1.0.2c" )){
			fix = "1.0.2c";
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

