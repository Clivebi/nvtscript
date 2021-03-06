if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902414" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "docuFORM Mercury WebApp Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5010.php" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100625/ZSL-2011-5010.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause Cross-Site
  Scripting by executing arbitrary codes with in the context of the affected application." );
	script_tag( name: "affected", value: "Mercury Web Application version 6.16a and 5.20" );
	script_tag( name: "insight", value: "Input passed to the 'this_url' and 'aa_sfunc' parameters in
  f_state.php, f_list.php, f_job.php and f_header.php, is not properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running docuFORM Mercury WebApplication is prone
  to multiple cross-site scripting vulnerabilities." );
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
res = http_get_cache( item: "/Mercury/login.php", port: port );
if(ContainsString( res, "<title>Mercury</title>" )){
	filename = "/Mercury/f_state.php";
	host = http_host_name( port: port );
	authVariables = "aa_afunc=call&aa_sfunc=1%3Cscript%3Ealert%28%27XSS-ATTACK" + "%27%29%3C%2Fscript%3E&aa_cfunc=OnAgentGetDeviceList&aa_sf" + "unc_args%255B%255D=0";
	req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
	res = http_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert('XSS-ATTACK')</script>" )){
		report = http_report_vuln_url( port: port, url: filename );
		security_message( port: port, data: report );
	}
}

