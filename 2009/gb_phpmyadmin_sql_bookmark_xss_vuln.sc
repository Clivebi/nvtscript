CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800595" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-2284" );
	script_bugtraq_id( 35543 );
	script_name( "phpMyAdmin SQL bookmark XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35649" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2009-5.php" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause XSS attacks and
  inject malicious web script or HTML code via a crafted SQL bookmarks." );
	script_tag( name: "affected", value: "phpMyAdmin version 3.0.x to 3.2.0.rc1." );
	script_tag( name: "insight", value: "This flaw arises because the input passed into SQL bookmarks is not
  adequately sanitised before using it in dynamically generated content." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 3.2.0.1 or later." );
	script_tag( name: "summary", value: "This host is running phpMyAdmin and is prone to Cross Site
  Scripting vulnerability." );
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
vers = ereg_replace( pattern: "-", string: vers, replace: "." );
if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.2.0.rc1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.2.0.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

