if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805710" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-07-02 13:11:22 +0530 (Thu, 02 Jul 2015)" );
	script_name( "CollabNet Subversion Edge Management Frontend Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with CollabNet
  Subversion Edge Management Frontend and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Get the installed version and check
  the version is vulnerable or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper input sanitization by 'listViewItem' parameter in 'index'
    script.

  - The password are stored in unsalted MD5, which can easily cracked by
    attacker.

  - Does not protect against brute forcing accounts.

  - Does not implement a strong password policy.

  - Does not require the old password for changing the password to a new one." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  read arbitrary local files, bypass authentication mechanisms." );
	script_tag( name: "affected", value: "CollabNet Subversion Edge Management Frontend 4.0.11" );
	script_tag( name: "solution", value: "Upgrade to 5.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jun/102" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132493/csem-xsrf.txt" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132488/csemfront-passwd.txt" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132494/csem-unsaltedhashes.txt" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132492/csem-passwordpolicy.txt" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3343 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.open.collab.net" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
coll_Port = http_get_port( default: 3343 );
for dir in nasl_make_list_unique( "/", "/csvn", http_cgi_dirs( port: coll_Port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/login/auth", port: coll_Port );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, ">CollabNet Subversion Edge Login<" )){
		version = eregmatch( string: buf, pattern: ">Release: ([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		if(vers){
			if(( version_is_equal( version: vers, test_version: "4.0.11" ) )){
				report = "Installed Version: " + vers + "\n" + "Fixed Version:     " + "5.0" + "\n";
				security_message( data: report, port: coll_Port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

