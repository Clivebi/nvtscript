CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807096" );
	script_version( "2021-03-10T13:27:48+0000" );
	script_cve_id( "CVE-2016-0800" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-10 13:27:48 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-03-03 12:23:09 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OpenSSL SSLv2 DROWN Attack Vulnerability (Linux)" );
	script_tag( name: "summary", value: "OpenSSL is prone to the DROWN attack vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due a padding oracle flaw found
  in the SSLv2 protocol, so that by exploiting the server's support of SSLv2,
  an attacker can decrypt properly secured TLS traffic." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to decrypt traffic between clients and non-vulnerable servers and to
  gain usernames, passwords, credit card numbers, emails, instant messages, and
  sensitive documents and also to impersonate a secure website and intercept or
  change the content the user sees." );
	script_tag( name: "affected", value: "OpenSSL versions before 1.0.1s and 1.0.2
  before 1.0.2g." );
	script_tag( name: "solution", value: "Upgrade to OpenSSL 1.0.1s or 1.0.2g or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20160301.txt" );
	script_xref( name: "URL", value: "https://drownattack.com/drown-attack-paper.pdf" );
	script_xref( name: "URL", value: "https://answers.uchicago.edu/page.php?id=61323" );
	script_xref( name: "URL", value: "http://arstechnica.com/security/2016/03/more-than-13-million-https-websites-imperiled-by-new-decryption-attack" );
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
if( version_is_less( version: vers, test_version: "1.0.1s" ) ){
	fix = "1.0.1s";
	VULN = TRUE;
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

