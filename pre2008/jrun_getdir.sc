if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10814" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2001-1510" );
	script_bugtraq_id( 3592 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Allaire JRun directory browsing vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Felix Huber" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_xref( name: "URL", value: "http://www.allaire.com/handlers/index.cfm?ID=22236&Method=Full" );
	script_tag( name: "solution", value: "From Macromedia Product Security Bulletin (MPSB01-13)

  Macromedia recommends, as a best practice, turning off directory
  browsing for the JRun Default Server in the following applications:

  - Default Application (the application with '/' mapping that causes
  the security problem)

  - Demo Application

  Also, make sure any newly created web application that uses the '/'
  mapping has directory browsing off.

  The changes that need to be made in the JRun Management Console or JMC:

  - JRun Default Server/Web Applications/Default User Application/File
  Settings/Directory Browsing Allowed set to FALSE.

  - JRun Default Server/Web Applications/JRun Demo/File Settings/
  Directory Browsing Allowed set to FALSE.

  Restart the servers after making the changes and the %3f.jsp request
  should now return a 403 forbidden. When this bug is fixed, the request
  (regardless of directory browsing setting) should return a '404 page
  not found'.

  The directory browsing property is called [file.browsedirs]. Changing
  the property via the JMC will cause the following changes:

  JRun 3.0 will write [file.browsedirs=false] in the local.properties
  file. (server-wide change)

  JRun 3.1 will write [file.browsedirs=false] in the webapp.properties
  of the application." );
	script_tag( name: "summary", value: "Allaire JRun 3.0/3.1 under a Microsoft IIS 4.0/5.0 platform has a
  problem handling malformed URLs. This allows a remote user to browse
  the file system under the web root (normally \\inetpub\\wwwroot)." );
	script_tag( name: "affected", value: "Under Windows NT/2000 (any service pack) and IIS 4.0/5.0:

  - JRun 3.0 (all editions)

  - JRun 3.1 (all editions)" );
	script_tag( name: "insight", value: "Upon sending a specially formed request to the web server, containing
  a '.jsp' extension makes the JRun handle the request. Example:

  http://example.com/%3f.jsp" );
	script_tag( name: "impact", value: "This vulnerability allows anyone with remote access to the web server
  to browse it and any directory within the web root." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/images", "/html", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/%3f.jsp", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(egrep( pattern: "Index of /", string: res ) || ( egrep( pattern: "Directory Listing", string: res ) )){
		ddir += http_report_vuln_url( port: port, url: install, url_only: TRUE ) + "\n";
	}
}
if(!isnull( ddir )){
	report = "The following directories were found to be browsable:\n\n" + ddir;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

