if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804244" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-2211", "CVE-2014-2212", "CVE-2014-2213", "CVE-2014-2214" );
	script_bugtraq_id( 65817, 65818, 65840, 65843 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-03-10 15:56:43 +0530 (Mon, 10 Mar 2014)" );
	script_name( "POSH Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with POSH and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  able to read the cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An input passed via the 'rssurl' parameter to 'addtoapplication.php'
  and 'error' parameter to 'login.php', which is not properly sanitised
  before using it.

  - It stores the username and md5 digest of the password in the cookie.

  - Improper validation of the 'redirect' parameter upon submission to the
  /posh/portal/scr_sendmd5.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials, execute SQL commands and obtain
  sensitive information." );
	script_tag( name: "affected", value: "POSH version before 3.3.0" );
	script_tag( name: "solution", value: "Upgrade to version POSH version 3.3.0 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56988" );
	script_xref( name: "URL", value: "http://www.sysdream.com/CVE-2014-2211_2214" );
	script_xref( name: "URL", value: "http://www.sysdream.com/system/files/POSH-3.2.1-advisory_0.pdf" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/posh" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
poshPort = http_get_port( default: 80 );
if(!http_can_host_php( port: poshPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/posh", "/portal", "/", http_cgi_dirs( port: poshPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	poshRes = http_get_cache( item: dir + "/login.php", port: poshPort );
	if(ContainsString( poshRes, ">Login<" ) && ContainsString( poshRes, "Email :" ) && ContainsString( poshRes, "Password :" ) && ContainsString( poshRes, "Memorise" )){
		url = dir + "/includes/plugins/mobile/scripts/login.php?" + "error=<script>alert(document.cookie)</script>";
		if(http_vuln_check( port: poshPort, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>" )){
			security_message( port: poshPort );
			exit( 0 );
		}
	}
}
exit( 99 );

