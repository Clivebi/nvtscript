if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800414" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4422" );
	script_bugtraq_id( 37483 );
	script_name( "JpGraph Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37832" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jpgraph_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "jpgraph/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an
  affected site and it result in XSS attack." );
	script_tag( name: "affected", value: "JpGraph version 3.0.6 and prior on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to the 'GetURLArguments()' function in 'jpgraph.php' not
  properly sanitising HTTP POST and GET parameter keys." );
	script_tag( name: "summary", value: "The host is running JpGraph and is prone to multiple Cross-Site
  Scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Apply the update from the referenced link." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/508586/100/0/threaded" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
jgphPort = http_get_port( default: 80 );
jgphVer = get_kb_item( "www/" + jgphPort + "/JpGraph" );
if(!jgphVer){
	exit( 0 );
}
jgphVer = eregmatch( pattern: "^(.+) under (/.*)$", string: jgphVer );
if(!safe_checks() && jgphVer[2] != NULL){
	url = jgphVer[2] + "/../src/Examples/csim_in_html_ex1.php?'/><script>alert('VT-XSS')</script>=arbitrary";
	request = http_get( item: url, port: jgphPort );
	response = http_send_recv( port: jgphPort, data: request );
	if(IsMatchRegexp( response, "^HTTP/1\\.[01] 200" ) && ContainsString( response, "\\'VT-XSS\\'" )){
		report = http_report_vuln_url( port: jgphPort, url: url );
		security_message( port: jgphPort, data: report );
		exit( 0 );
	}
}
if(jgphVer[1] != NULL){
	if(version_is_less_equal( version: jgphVer[1], test_version: "3.0.6" )){
		security_message( jgphPort );
	}
}

