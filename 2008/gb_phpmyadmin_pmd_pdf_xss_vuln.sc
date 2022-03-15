CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800301" );
	script_version( "$Revision: 14010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-4775" );
	script_bugtraq_id( 31928 );
	script_name( "phpMyAdmin pmd_pdf.php Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32449/" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2008/Oct/0199.html" );
	script_tag( name: "summary", value: "This host is running phpMyAdmin and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "insight", value: "Input passed to the 'db' parameter in pmd_pdf.php file is not properly
  sanitised before returning to the user." );
	script_tag( name: "affected", value: "phpMyAdmin phpMyAdmin versions 3.0.1 and prior on all running platform." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin 3.0.1.1 or later." );
	script_tag( name: "impact", value: "Allows execution of arbitrary HTML and script code, and steal cookie-based
  authentication credentials." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_less_equal( version: vers, test_version: "3.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.0.1.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
