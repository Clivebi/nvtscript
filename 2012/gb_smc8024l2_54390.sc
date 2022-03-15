if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103513" );
	script_bugtraq_id( 54390 );
	script_cve_id( "CVE-2012-2974" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "SMC Networks SMC8024L2 Switch Web Interface Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54390" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/377915" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-07-12 10:05:05 +0200 (Thu, 12 Jul 2012)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The SMC Networks SMC8024L2 switch is prone to a remote authentication-
  bypass vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to gain unauthorized administrative
  access to all configuration pages to affected devices." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/index.html";
buf = http_get_cache( port: port, item: url );
if(ContainsString( buf, "<title>SMC Networks Web Interface" )){
	url = "/status/status_ov.html";
	if(http_vuln_check( port: port, url: url, pattern: "<title>Status Overview", extra_check: make_list( "macAddress",
		 "opVersion",
		 "systemName" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

