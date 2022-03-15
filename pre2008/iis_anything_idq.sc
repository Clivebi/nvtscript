if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10492" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1065 );
	script_cve_id( "CVE-2000-0071" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "IIS IDA/IDQ Path Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Filipe Custodio" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Select 'Preferences ->Home directory ->Application',
  and check the checkbox 'Check if file exists' for the ISAPI mappings of your server." );
	script_tag( name: "summary", value: "IIS 4.0 allows a remote attacker to obtain the real pathname
  of the document root by requesting non-existent files with .ida or .idq extensions." );
	script_tag( name: "impact", value: "An attacker may use this flaw to gain more information about
  the remote host, and hence make more focused attacks." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
sig = http_get_remote_headers( port: port );
if(!sig || !ContainsString( sig, "IIS" )){
	exit( 0 );
}
url = "/anything.idq";
req = http_get( item: url, port: port );
r = http_send_recv( port: port, data: req );
str = egrep( pattern: "^<HTML>", string: r ) - "<HTML>";
str = tolower( str );
if( egrep( pattern: "[a-z]\\:\\\\.*anything", string: str ) ){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	url = "/anything.ida";
	req = http_get( item: url, port: port );
	r = http_send_recv( port: port, data: req );
	str = egrep( pattern: "^<HTML>", string: r ) - "<HTML>";
	str = tolower( str );
	if(egrep( pattern: "[a-z]\\:\\\\.*anything", string: str )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

