if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900750" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)" );
	script_cve_id( "CVE-2010-0976", "CVE-2010-0984" );
	script_name( "Acidcat CMS Multiple Vulnerabilities" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38084" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55329" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55331" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/10972" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to:

  - 'install.asp' and other 'install_*.asp' scripts which can be accessed
  even after the installation finishes, which might allow remote attackers
  to restart the installation process.

  - improper access restrictions to the 'acidcat_3.mdb' database file in
  the databases directory. An attacker can download the database containing
  credentials via a direct request for databases/acidcat_3.mdb." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Acidcat CMS and is prone to multiple
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to restart
  the installation process and an attacker can download the database containing
  credentials via a direct request for databases/acidcat_3.mdb." );
	script_tag( name: "affected", value: "Acidcat CMS 3.5.3 and prior" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/acidcat", "/Acidcat", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/main_login.asp" ), port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, ">Acidcat ASP CMS" )){
		req = http_get( item: NASLString( dir, "/install.asp" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "Welcome to the Acidcat CMS installation guide" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

