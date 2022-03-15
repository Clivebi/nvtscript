if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10577" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 2280 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Check for bdir.htr files" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "solution", value: "If you do not need these files, then delete them,
  otherwise use suitable access control lists to ensure that
  the files are not world-readable." );
	script_tag( name: "summary", value: "The file bdir.htr is a default IIS files which can give
  a malicious user a lot of unnecessary information about your file system." );
	script_tag( name: "impact", value: "Specifically, the bdir.htr script allows
  the user to browse and create files on hard drive.  As this
  includes critical system files, it is highly possible that
  the attacker will be able to use this script to escalate
  privileges and gain 'Administrator' access.

  Example: http://example.com/scripts/iisadmin/bdir.htr??c:" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
sig = http_get_remote_headers( port: port );
if(!sig || !ContainsString( sig, "Server: Microsoft/IIS" )){
	exit( 0 );
}
url = "/scripts/iisadmin/bdir.htr";
if(http_is_cgi_installed_ka( item: url, port: port )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}

