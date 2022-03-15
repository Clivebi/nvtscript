if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802132" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2011-5287" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "HESK Multiple Cross-site Scripting (XSS) Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519148" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/multiple_xss_in_hesk.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103733/hesk-xss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to improper validation of

  - input passed via the 'hesk_settings[tmp_title]' and 'hesklang[ENCODING]'
    parameters to '/inc/header.inc.php'.

  - input passed via 'hesklang[attempt]' parameter to various files in '/inc/'
    directory.

  - input appended to the URL after '/language/en/text.php', before being
  returned to the user." );
	script_tag( name: "solution", value: "Upgrade to HESK version 2.3 or later." );
	script_tag( name: "summary", value: "This host is running HESK and is prone to multiple cross-site
  scripting vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of affected website." );
	script_tag( name: "affected", value: "HESK version 2.2 and prior." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/hesk", "/Hesk", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">Powered by <" ) && ContainsString( res, "> HESK&" )){
		url = NASLString( dir, "/inc/header.inc.php?hesklang[ENCODING]=\"><script>" + "alert('", vt_strings["lowercase"], "');</script>" );
		if(http_vuln_check( port: port, url: url, pattern: "><script>alert" + "\\('" + vt_strings["lowercase"] + "'\\);</script>", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

