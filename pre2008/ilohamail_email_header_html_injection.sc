CPE = "cpe:/a:ilohamail:ilohamail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14634" );
	script_version( "2021-04-09T11:48:55+0000" );
	script_tag( name: "last_modification", value: "2021-04-09 11:48:55 +0000 (Fri, 09 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10668 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "IlohaMail Email Header HTML Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "ilohamail_detect.sc" );
	script_mandatory_keys( "ilohamail/detected" );
	script_tag( name: "solution", value: "Upgrade to IlohaMail version 0.8.13 or later." );
	script_tag( name: "summary", value: "The remote web server contains a PHP script which is vulnerable to a cross site
  scripting vulnerability.

  Description :

  The target is running at least one instance of IlohaMail version 0.8.12 or earlier. Such versions do not properly
  sanitize message headers, leaving users vulnerable to XSS attacks. For example, a remote attacker could inject
  Javascript code that steals the user's session cookie and thereby gain access to that user's account." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^0\\.([0-7].*|8\\.([0-9]|1[0-2])(-Devel)?$)" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.13", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

