CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100775" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)" );
	script_bugtraq_id( 42874 );
	script_cve_id( "CVE-2010-2958" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "phpMyAdmin Debug Backtrace Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42874" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2010-6.php" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.git.sourceforge.net/git/gitweb.cgi?p=phpmyadmin/phpmyadmin;a=commitdiff;h=133a77fac7d31a38703db2099a90c1b49de62e37" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to phpMyAdmin 3.3.6 are vulnerable. Other versions may
  also be affected." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied data." );
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
if(version_in_range( version: vers, test_version: "3", test_version2: "3.3.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.3.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

