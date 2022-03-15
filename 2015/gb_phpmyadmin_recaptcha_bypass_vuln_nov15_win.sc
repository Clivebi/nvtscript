CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806548" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-6830" );
	script_bugtraq_id( 76674 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-11-24 10:32:31 +0530 (Tue, 24 Nov 2015)" );
	script_name( "phpMyAdmin Security Bypass Vulnerability Nov15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin and
  is prone to reCaptcha bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in
  'libraries/plugins/auth/AuthenticationCookie.class.php' script while
  implementing multiple-reCaptcha protection mechanism so that it provide a
  correct response to a single reCaptcha." );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow
  remote attackers to bypass multiple-reCaptcha protection mechanism." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.3.x before 4.3.13.2
  and 4.4.x before 4.4.14.1 on Windows" );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin 4.3.13.2 or 4.4.14.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2015-4" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
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
if( IsMatchRegexp( vers, "^4\\.3" ) ){
	if(version_is_less( version: vers, test_version: "4.3.13.2" )){
		fix = "4.3.13.2";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( vers, "^4\\.4" )){
		if(version_is_less( version: vers, test_version: "4.4.14.1" )){
			fix = "4.4.14.1";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

