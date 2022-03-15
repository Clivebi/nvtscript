if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803961" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-2651" );
	script_bugtraq_id( 62907 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-11-07 16:32:49 +0530 (Thu, 07 Nov 2013)" );
	script_name( "BoltWire Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials." );
	script_tag( name: "affected", value: "BoltWire version 3.5 and earlier" );
	script_tag( name: "insight", value: "An error exists in the index.php script which fails to properly sanitize
user-supplied input to 'p' and 'content' parameter before using." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether
it is able to read the string or not." );
	script_tag( name: "summary", value: "This host is installed with BoltWire and is prone to multiple cross-site
scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62907" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/87809" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/123558" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2013-10/0033.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/bolt", "/boltwire", "/field", "/bolt/field", "/boltwire/field", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(isnull( res )){
		continue;
	}
	if(res && ContainsString( res, "<title>BoltWire: Main</title>" ) && ContainsString( res, "Radical Results!" )){
		url = url + "?p=%253Cscript%253Ealert(%2527XSS-TEST%2527)%253B%253C%252Fscript%253E";
		match = "<script>alert\\('XSS-TEST'\\);</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: match )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: url );
			exit( 0 );
		}
	}
}

