if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10576" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-1999-0737" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Check for dangerous IIS default files" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/banner" );
	script_tag( name: "solution", value: "If you do not need these files, then delete them, otherwise
  use suitable access control lists to ensure that the files are not world-readable." );
	script_tag( name: "summary", value: "The file viewcode.asp is a default IIS files which can give a
  malicious user a lot of unnecessary information about your file system or source files.

  Specifically, viewcode.asp can allow a remote user to potentially read any file on a webserver
  hard drive.

  Example: http://example.com/pathto/viewcode.asp?source=../../../../../../autoexec.bat" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
sig = http_get_remote_headers( port: port );
if(!sig || !ContainsString( sig, "IIS" )){
	exit( 0 );
}
urls = make_list( "/Sites/Knowledge/Membership/Inspired/ViewCode.asp",
	 "/Sites/Knowledge/Membership/Inspiredtutorial/Viewcode.asp",
	 "/Sites/Samples/Knowledge/Membership/Inspired/ViewCode.asp",
	 "/Sites/Samples/Knowledge/Membership/Inspiredtutorial/ViewCode.asp",
	 "/Sites/Samples/Knowledge/Push/ViewCode.asp",
	 "/Sites/Samples/Knowledge/Search/ViewCode.asp",
	 "/SiteServer/Publishing/viewcode.asp" );
list = "";
for url in urls {
	if(http_is_cgi_installed_ka( item: url, port: port )){
		list = NASLString( list, "\\n", url );
	}
}
if(strlen( list )){
	report = "The following files were found on the remote web server:" + list;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

