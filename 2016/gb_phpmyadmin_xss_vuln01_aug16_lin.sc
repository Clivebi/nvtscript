CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808254" );
	script_version( "$Revision: 12051 $" );
	script_cve_id( "CVE-2016-5099" );
	script_bugtraq_id( 90877 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-04 13:01:28 +0530 (Thu, 04 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "phpMyAdmin Double URL Decoding Cross Site Scripting Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with phpMyAdmin
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient validation
  of user supplied inputs that are mishandled during double URL decoding." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via special characters." );
	script_tag( name: "affected", value: "phpMyAdmin versions 4.4.x before 4.4.15.6
  and 4.6.x before 4.6.2 on Linux." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 4.4.15.6 or
  4.6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2016-16" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc", "os_detection.sc" );
	script_mandatory_keys( "phpMyAdmin/installed", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!phpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!phpVer = get_app_version( cpe: CPE, port: phpPort )){
	exit( 0 );
}
if( IsMatchRegexp( phpVer, "^(4\\.4)" ) ){
	if(version_is_less( version: phpVer, test_version: "4.4.15.6" )){
		fix = "4.4.15.6";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( phpVer, "^(4\\.6)" )){
		if(version_is_less( version: phpVer, test_version: "4.6.2" )){
			fix = "4.6.2";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: fix );
	security_message( port: phpPort, data: report );
	exit( 0 );
}

