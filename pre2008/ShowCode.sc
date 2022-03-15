if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10007" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 167 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-1999-0736" );
	script_name( "ShowCode possible" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 1999 Immo Goltz <Immo.Goltz@gecits-eu.com>" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.l0pht.com/advisories.html" );
	script_tag( name: "solution", value: "For production servers, sample files should never be installed, so
  delete the entire /msadc/samples directory. If you must have the
  'showcode.asp' capability on a development server, the 'showcode.asp' file
  should be modified to test for URLs with '..' in them and deny those requests." );
	script_tag( name: "summary", value: "Internet Information Server (IIS) 4.0 ships with a set of sample files to
  help web developers learn about Active Server Pages (ASP)." );
	script_tag( name: "insight", value: "One of these sample files, 'showcode.asp'
  (installed in /msadc/Samples/SELECTOR/), is
  designed to view the source code of the sample applications via a web browser.
  The 'showcode.asp' file does inadequate security checking and allows anyone
  with a web browser to view the contents of any text file on the web server.
  This includes files that are outside of the document root of the web server.

  The 'showcode.asp' file is installed by default at the URL:
  http://www.example.com/msadc/Samples/SELECTOR/showcode.asp
  It takes 1 argument in the URL, which is the file to view.
  The format of this argument is: source=/path/filename

  This is a fairly dangerous sample file since it can view the contents of any
  other files on the system. The author of the ASP file added a security check to
  only allow viewing of the sample files which were in the '/msadc' directory on
  the system. The problem is the security check does not test for the '..'
  characters within the URL. The only checking done is if the URL contains the
  string '/msadc/'. This allows URLs to be created that view, not only files
  outside of the samples directory, but files anywhere on the entire file
  system that the web server's document root is on.

  The full description can be found at the referenced link." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
url = "/msadc/Samples/SELECTOR/showcode.asp";
if(http_is_cgi_installed_ka( item: url, port: port )){
	files = traversal_files( "windows" );
	for file in keys( files ) {
		url = "/msadc/Samples/SELECTOR/showcode.asp?source=/msadc/Samples/../../../../../" + files[file];
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	exit( 99 );
}
exit( 0 );

