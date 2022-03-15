if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800758" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)" );
	script_cve_id( "CVE-2010-1272" );
	script_bugtraq_id( 38522 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Gnat-TGP 'DOCUMENT_ROOT' Parameter Remote File Include Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56675" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11621" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Gnat-TGP version 1.2.20 and prior" );
	script_tag( name: "insight", value: "The flaw is due to the error in the 'DOCUMENT_ROOT' parameter,
  which allows remote attackers to send a specially-crafted URL request to the 'tgpinc.php' script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Gnat-TGP and is prone remote file include
  vulnerability" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/gnat-tgp", "/Gnat-TGP", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/gnat/admin/index.php", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "Gnat-TGP" ) && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		version = eregmatch( pattern: ";([0-9.]+)", string: res );
		if(version[1] != NULL){
			if(version_is_less_equal( version: version[1], test_version: "1.2.20" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

