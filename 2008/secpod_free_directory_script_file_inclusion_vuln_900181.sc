if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900181" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_cve_id( "CVE-2008-6305" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_name( "Free Directory Script 'API_HOME_DIR' File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7155" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32745" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker add, modify or delete files
  from the server and can let the attacker install trojans or backdoors." );
	script_tag( name: "insight", value: "The Error occurs when passing an input parameter into the 'API_HOME_DIR' in
  'init.php' file which is not properly verified before being used to include
  files. This can be exploited to include arbitrary files from local or external resources." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Free Directory Script and is prone to
  File Inclusion Vulnerability." );
	script_tag( name: "affected", value: "Free Directory Script version 1.1.1 and prior." );
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
for path in nasl_make_list_unique( "/FreeDirectory", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: path + "/index.php", port: port );
	if(!rcvRes){
		continue;
	}
	if(egrep( pattern: "Free Directory Script", string: rcvRes ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes )){
		pattern = "FDS Version (0(\\..*)|1\\.(0(\\..*)?|1(\\.[01])?))($|[^.0-9])";
		if(egrep( pattern: pattern, string: rcvRes )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

