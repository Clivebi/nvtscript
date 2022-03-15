if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15746" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2004-1050" );
	script_bugtraq_id( 11515 );
	script_name( "Bofra Virus Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Brian Smith-Sweeney" );
	script_family( "Malware" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 1639 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://securityresponse.symantec.com/avcenter/venc/data/w32.bofra.c@mm.html" );
	script_tag( name: "solution", value: "Re-install the remote system." );
	script_tag( name: "summary", value: "The remote host seems to have been infected with the Bofra virus or one of its
  variants, which infects machines via an Internet Explorer IFRAME exploit.

  It is very likely this system has been compromised." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
port = 1639;
if(!get_port_state( port )){
	exit( 0 );
}
url = "/reactor";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
hex_res = hexstr( res );
if(egrep( pattern: "<IFRAME SRC=file://", string: res ) || ContainsString( hex_res, "3c0049004600520041004d00450020005300520043003d00660069006c0065003a002f002f00" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

