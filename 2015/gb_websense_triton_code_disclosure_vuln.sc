CPE = "cpe:/a:websense:triton";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106002" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-06-03 10:18:34 +0700 (Wed, 03 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Websense Triton Source Code Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_websense_triton_detect.sc" );
	script_mandatory_keys( "websense_triton/installed" );
	script_tag( name: "summary", value: "Websense Triton is vulnerable to a source code disclosure
vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check
the response" );
	script_tag( name: "insight", value: "By appending a double quote character after JSP URLs, Websense
will return the source code of the JSP instead of executing the JSP." );
	script_tag( name: "impact", value: "An attacker can use this vulnerability to inspect parts of
Websense's source code in order to gain more knowledge about Websense's internals." );
	script_tag( name: "affected", value: "Websense Triton v7.8.3 and v7.7" );
	script_tag( name: "solution", value: "Install the hotfix 02 for version 7.8.4 or update to version
8.0." );
	script_xref( name: "URL", value: "https://www.securify.nl/advisory/SFY20140907/source_code_disclosure_of_websense_triton_jsp_files_via_double_quote_character.html" );
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
url = dir + "/triton/login/pages/certificateDone.jsp%22";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<%@page import=\"com.websense.java.eip.client.login.BBLogin\"%>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: url );
	exit( 0 );
}
exit( 0 );

