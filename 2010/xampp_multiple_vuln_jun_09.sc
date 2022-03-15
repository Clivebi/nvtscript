CPE = "cpe:/a:apachefriends:xampp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100483" );
	script_version( "2021-06-24T02:07:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 02:07:35 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-02-02 21:07:02 +0100 (Tue, 02 Feb 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "XAMPP Multiple Vulnerabilities (Jun 2009)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xampp_detect.sc" );
	script_mandatory_keys( "xampp/detected" );
	script_tag( name: "summary", value: "XAMPP is prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "1. showcode.php Local File Include Vulnerability

  An attacker can exploit this vulnerability to view files and execute
  local scripts in the context of the webserver process. This may aid
  in further attacks.

  2. Multiple Cross Site Scripting Vulnerabilities

  An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.

  3. Multiple SQL Injection Vulnerabilities

  Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database." );
	script_tag( name: "affected", value: "These issues affect XAMPP 1.6.8 and prior. Other versions may be
  affected as well." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37997" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37998" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37999" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3230/" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3220/" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3257/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.6.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

