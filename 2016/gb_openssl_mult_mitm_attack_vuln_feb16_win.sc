CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806675" );
	script_version( "2021-03-10T13:27:48+0000" );
	script_cve_id( "CVE-2015-3197", "CVE-2015-4000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-10 13:27:48 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-02-01 16:21:31 +0530 (Mon, 01 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenSSL Multiple MitM Attack Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple man-in-the-middle (MitM) attack vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws found,

  - The way malicious SSL/TLS clients could negotiate SSLv2 ciphers that have
    been disabled on the server.

  - When a DHE_EXPORT ciphersuite is enabled on a server but not on a client,
    does not properly convey a DHE_EXPORT choice." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to conduct man-in-the-middle attack." );
	script_tag( name: "affected", value: "OpenSSL versions 1.0.1x before 1.0.1r and
  1.0.2x before 1.0.2f." );
	script_tag( name: "solution", value: "Upgrade to OpenSSL 1.0.1r or 1.0.2f or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20160128.txt" );
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
	if(version_is_less( version: vers, test_version: "1.0.1r" )){
		VULN = TRUE;
		fix = "1.0.1r";
	}
}
else {
	if(IsMatchRegexp( vers, "^1\\.0\\.2" )){
		if(version_is_less( version: vers, test_version: "1.0.2f" )){
			VULN = TRUE;
			fix = "1.0.2f";
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

