if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100010" );
	script_version( "2021-04-19T14:01:20+0000" );
	script_bugtraq_id( 33643 );
	script_tag( name: "last_modification", value: "2021-04-19 14:01:20 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-03-06 13:13:19 +0100 (Fri, 06 Mar 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ClearBudget Invalid '.htaccess' Unauthorized Access Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/33643" );
	script_tag( name: "summary", value: "ClearBudget is prone to an unauthorized-access vulnerability
  because it fails to properly restrict access to certain directories." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to gain access to
  database contents. Information harvested can lead to further attacks." );
	script_tag( name: "affected", value: "ClearBudget version 0.6.1 is known to be vulnerable. Other
  versions may also be affected." );
	script_tag( name: "solution", value: "The vendor released an update to address this issue. Please see
  the references for more information." );
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
for dir in nasl_make_list_unique( "/ClearBudget", "/cb", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/db/budget.sqlite";
	if(http_vuln_check( port: port, url: url, pattern: "SQLite", check_header: TRUE, icase: FALSE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

