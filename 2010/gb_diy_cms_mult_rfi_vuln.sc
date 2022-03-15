if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801512" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3206" );
	script_name( "DiY-CMS Multiple Remote File Inclusion Vulnerabilities" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61454" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14822/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1008-exploits/diycms-rfi.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in 'modules/guestbook/blocks/control.block.php', which is not
  properly validating the input passed to the 'lang' parameter.

  - An error in the 'index.php', which is not properly validating the input
  passed to 'main_module' parameter.

  - An error in the 'includes/general.functions.php', which is not properly
  validating the input passed to 'getFile' parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running DiY-CMS and is prone to multiple remote
  file inclusion vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server." );
	script_tag( name: "affected", value: "DiY-CMS version 1.0." );
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
for dir in nasl_make_list_unique( "/diycms/diy", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "<title>Welcome - Do It Yourself CMS - Using DiY-CMS<" )){
		version = eregmatch( pattern: "DiY-CMS ([0-9.]+)", string: res );
		if(version[1] != NULL){
			if(version_is_equal( version: version[1], test_version: "1.0" )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

