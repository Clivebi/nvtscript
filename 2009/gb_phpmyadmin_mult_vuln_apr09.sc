CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800381" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-04-20 14:33:23 +0200 (Mon, 20 Apr 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1148", "CVE-2009-1149", "CVE-2009-1150", "CVE-2009-1151" );
	script_bugtraq_id( 34251, 34253, 34236 );
	script_name( "phpMyAdmin 2.11.x < 2.11.9.4 / 3.0.x < 3.1.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34430" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2009-1.php" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2009-2.php" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2009-3.php" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause XSS, Directory Traversal
  attacks or can injection malicious PHP Codes to gain sensitive information about the remote host." );
	script_tag( name: "affected", value: "phpMyAdmin version 2.11.x to 2.11.9.4 and 3.0.x to 3.1.3." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - BLOB streaming feature in 'bs_disp_as_mime_type.php' causes CRLF Injection
  which lets the attacker inject arbitrary data in the HTTP headers through
  the 'c_type' and 'file_type' parameters.

  - XSS Vulnerability in 'display_export.lib.php' as its not sanitizing the
  'pma_db_filename_template' parameter.

  - Static code injection vulnerability in 'setup.php' which can be used to
  inject PHP Codes.

  - Filename 'bs_disp_as_mime_type.php' which is not sanitizing user supplied
  inputs in the filename variable which causes directory traversal attacks." );
	script_tag( name: "summary", value: "This host is running phpMyAdmin and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to version 2.11.9.5 or 3.1.3.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "2.11", test_version2: "2.11.9.4" ) || version_in_range( version: vers, test_version: "3.0", test_version2: "3.1.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.11.9.5/3.1.3.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

