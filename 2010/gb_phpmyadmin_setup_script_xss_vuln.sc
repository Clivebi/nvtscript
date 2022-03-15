CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801286" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)" );
	script_cve_id( "CVE-2010-3263" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "phpMyAdmin Setup Script Request Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41210" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61675" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2010-7.php" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "phpMyAdmin versions 3.x before 3.3.7" );
	script_tag( name: "insight", value: "The flaw is caused by an unspecified input validation error when processing
  spoofed requests sent to setup script, which could be exploited by attackers
  to cause arbitrary scripting code to be executed on the user's browser session
  in the security context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 3.3.7 or later." );
	script_tag( name: "summary", value: "The host is running phpMyAdmin and is prone to Cross-Site Scripting
  Vulnerability." );
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
if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.3.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.3.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

