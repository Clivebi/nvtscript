CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808253" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2016-5099" );
	script_bugtraq_id( 90877 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-08-04 13:01:28 +0530 (Thu, 04 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "phpMyAdmin Double URL Decoding Cross Site Scripting Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient validation
  of user supplied inputs that are mishandled during double URL decoding." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via special characters." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.4.x before 4.4.15.6
  and 4.6.x before 4.6.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 4.4.15.6 or
  4.6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-16" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( vers, "^4\\.4" ) ){
	if(version_is_less( version: vers, test_version: "4.4.15.6" )){
		fix = "4.4.15.6";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( vers, "^4\\.6" )){
		if(version_is_less( version: vers, test_version: "4.6.2" )){
			fix = "4.6.2";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}

