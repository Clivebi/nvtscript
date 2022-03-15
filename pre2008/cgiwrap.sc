if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10041" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1238, 777 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-1530", "CVE-2000-0431" );
	script_name( "Cobalt RaQ2 cgiwrap" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 1999 Mathieu Perrin" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your Cobalt RaQ to apply fix." );
	script_tag( name: "summary", value: "'cgiwrap' is installed. If you are running an unpatched Cobalt RaQ,
  the version of cgiwrap distributed with that system has a known security flaw that lets anyone execute
  arbitrary commands with the privileges of the http daemon (root or nobody).

  This flaw exists only on the Cobalt modified cgiwrap. Standard builds of cgiwrap are not affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/cgiwrap";
	if(http_is_cgi_installed_ka( item: url, port: port )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

