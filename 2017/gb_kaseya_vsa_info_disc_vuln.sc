CPE = "cpe:/a:kaseya:virtual_system_administrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106739" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2017-04-10 14:46:29 +0200 (Mon, 10 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Kaseya VSA Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kaseya_vsa_detect.sc" );
	script_mandatory_keys( "kaseya_vsa/installed" );
	script_tag( name: "summary", value: "Kaseya VSA is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a HTTP request and checks the response." );
	script_tag( name: "insight", value: "Requests to /install/kaseya.html reveals sensitive information about the
application and its underlying system." );
	script_tag( name: "impact", value: "An unauthenticated attacker may obtain sensitive information about the
application and its underlying system." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.osisecurity.com.au/kaseya-information-disclosure-vulnerability.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/install/kaseya.html";
if(http_vuln_check( port: port, url: url, pattern: "IFX_INSTALLED_VERSION", check_header: TRUE, extra_check: "SUPPORTDIR" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

