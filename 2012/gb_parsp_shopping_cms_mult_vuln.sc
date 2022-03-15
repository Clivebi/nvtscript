if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802575" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-01 15:28:20 +0530 (Wed, 01 Feb 2012)" );
	script_name( "Parsp Shopping CMS Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://1337day.com/exploits/17418" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18409/" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2012010198" );
	script_xref( name: "URL", value: "http://www.exploitsdownload.com/search/Arab" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108953/parspshoppingcms-xssdisclose.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected
  site and gain th sensitive information related to PHP." );
	script_tag( name: "affected", value: "Parsp Shopping CMS version V5 and prior." );
	script_tag( name: "insight", value: "The flaws are due to an:

  - Input passed to the 'advanced_search_in_category' parameter in 'index.php'
   is not properly sanitised before being returned to the user.

  - Error in 'phpinfo.php' script, this can be exploited to gain knowledge
   of sensitive information by requesting the file directly." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Parsp Shopping CMS and is prone to multiple
  vulnerabilities." );
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
for dir in nasl_make_list_unique( "/", "/parsp", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(egrep( pattern: ">powered by .*>www.parsp.com<", string: rcvRes )){
		sndReq = http_get( item: dir + "/phpinfo.php", port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		if(ContainsString( rcvRes, "<title>phpinfo" ) && ContainsString( rcvRes, ">PHP Core<" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

