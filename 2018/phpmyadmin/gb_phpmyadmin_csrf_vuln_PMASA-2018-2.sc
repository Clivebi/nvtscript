CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813158" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-10188" );
	script_bugtraq_id( 103936 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-21 16:39:00 +0000 (Mon, 21 May 2018)" );
	script_tag( name: "creation_date", value: "2018-05-02 17:13:20 +0530 (Wed, 02 May 2018)" );
	script_name( "phpMyAdmin Cross-Site Request Forgery Vulnerability-PMASA-2018-2" );
	script_tag( name: "summary", value: "The host is installed with phpMyAdmin and
  is prone to cross site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to failure in the
  '/sql.php' script to properly verify the source of HTTP request." );
	script_tag( name: "impact", value: "Successful exploitation of this cross-site
  request forgery (CSRF) allows an attacker to execute arbitrary SQL statement
  by sending a malicious request to a logged in user." );
	script_tag( name: "affected", value: "phpMyAdmin version 4.8.0" );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 4.8.0-1 or
  newer version or apply patch from vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.phpmyadmin.net/security/PMASA-2018-2/" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44496/" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_mandatory_keys( "phpMyAdmin/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!phport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: phport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(vers == "4.8.0"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.8.0-1", install_path: path );
	security_message( port: phport, data: report );
	exit( 0 );
}
exit( 0 );

