if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10799" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3518 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "IBM-HTTP-Server View Code" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Felix Huber" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ibm_http_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ibm/http_server/detected" );
	script_tag( name: "summary", value: "IBM's HTTP Server on the AS/400 platform is vulnerable to an attack
  that will show the source code of the page -- such as an .html or .jsp
  page -- by attaching an '/' to the end of a URL.

  Example:
  http://www.example.com/getsource.jsp/" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
files = make_list( "/index.html",
	 "/index.htm",
	 "/index.jsp",
	 "/default.html",
	 "/default.htm",
	 "/default.jsp",
	 "/home.html",
	 "/home.htm",
	 "/home.jsp" );
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
kb_files = http_get_kb_file_extensions( port: port, host: host, ext: "jsp" );
if(!isnull( kb_files )){
	files = nasl_make_list_unique( files, kb_files );
}
for file in files {
	url = file + "/";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(isnull( res )){
		continue;
	}
	if(ContainsString( res, "Content-Type: www/unknown" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

