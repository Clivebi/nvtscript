if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11079" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3100 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-1108" );
	script_name( "Snapstream PVS web directory traversal" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8129 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or change it!" );
	script_tag( name: "summary", value: "It is possible to read arbitrary files on the remote
  Snapstream PVS server by prepending ../../ in front on the file name.

  It may also be possible to read ../ssd.ini which contains many information on the
  system (base directory, usernames & passwords)." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8129 );
files = make_list( "/../ssd.ini",
	 "/../../../../autoexec.bat",
	 "/../../../winnt/repair/sam" );
for file in files {
	ok = http_is_cgi_installed_ka( port: port, item: file );
	if(ok){
		report = http_report_vuln_url( port: port, url: file );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

