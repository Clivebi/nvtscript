if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801513" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3209", "CVE-2010-3212" );
	script_name( "Seagull SQL Injection and Multiple Remote File Inclusion Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41169" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14838/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1008-exploits/seagull-rfi.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1008-exploits/seagull-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the 'Config/Container.php', which is not properly validating the
  input passed to 'includeFile' parameter.

  - An error in the 'fog/lib/pear/HTML/QuickForm.php', which is not properly
  validating the input passed to 'includeFile' parameter.

  - An error in the 'fog/lib/pear/DB/NestedSet.php', which is not properly
  validating the input passed to 'driverpath' parameter.

  - An error in the 'fog/lib/pear/DB/NestedSet/Output.php', which is not properly
  validating the input passed to 'path' parameter.

  - An SQL injection error in 'index.php', which allows remote attackers to
  execute arbitrary SQL commands via the frmQuestion parameter in a retrieve
  action, in conjunction with a user/password PATH_INFO." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Seagull and is prone to SQL injection and
  multiple remote file inclusion vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server and to execute arbitrary SQL commands." );
	script_tag( name: "affected", value: "Seagull version 0.6.7" );
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
for dir in nasl_make_list_unique( "/seagull/www", "/Seagull", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, "<title>Seagull Framework :: Home<" )){
		req = http_get( item: NASLString( dir, "/index.php/user/password/?action=" + "retrieve&frmEmail=111-222-1933email@add" + "ress.tst&frmQuestion=1'[SQLI]&frmAnswer" + "=111-222-1933email@address.tst&submitte" + "d=retrieve" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "this->whereAdd" ) && ContainsString( res, "Object of class DB_" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

