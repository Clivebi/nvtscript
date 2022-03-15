CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806653" );
	script_version( "2021-03-10T05:21:16+0000" );
	script_cve_id( "CVE-2015-3193", "CVE-2015-1794" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-10 05:21:16 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-12-18 08:22:17 +0530 (Fri, 18 Dec 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenSSL Multiple Vulnerabilities -01 Dec15 (Windows)" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the montgomery squaring implementation within the
  crypto/bn/asm/x86_64-mont5.pl script.

  - An error in the ssl3_get_key_exchange function in ssl/s3_clnt.c script." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to conduct denial of service attack and gain access to potentially
  sensitive information." );
	script_tag( name: "affected", value: "OpenSSL versions 1.0.2 before 1.0.2e on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to OpenSSL 1.0.2e or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://openssl.org/news/secadv/20151203.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( vers, "^1\\.0\\.2" ) && version_is_less( version: vers, test_version: "1.0.2e" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.0.2e", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

