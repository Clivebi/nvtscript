if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117476" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-28169" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-09 09:00:38 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-04 16:15:00 +0000 (Sun, 04 Jul 2021)" );
	script_name( "'/%2557EB-INF/' Information Disclosure Vulnerability (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://github.com/eclipse/jetty.project/security/advisories/GHSA-gwcr-j4wh-j3cq" );
	script_tag( name: "summary", value: "Various application or web servers / products are prone to an
  information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "affected", value: "The following products are known to be affected:

  - Eclipse Jetty versions before 9.4.41, 10.0.3 and 11.0.3

  Other products might be affected as well." );
	script_tag( name: "insight", value: "The servlet specification prohibits servlet containers from
  serving resources in the '/WEB-INF' and '/META-INF' directories of a web application archive
  directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that exposes this
  information if the client requests a URL like this instead:

  http://example.com/%2557EB-INF/web.xml

  (note the doubled encoding '%2557' of 'W')." );
	script_tag( name: "impact", value: "Based on the information provided in this file an attacker might
  be able to gather additional info and / or sensitive data about the application / the application
  / web server." );
	script_tag( name: "solution", value: "The following vendor fixes are known:

  - Update Eclipse Jetty to version 9.4.41, 10.0.3, 11.0.3 or later.

  For other products please contact the vendor for more information on possible fixes." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
base_pattern = "^\\s*<(web-app( .+|>$)|servlet>$)";
extra_pattern = "^\\s*</(web-app|servlet)>$";
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/concat?", "/static?", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/WEB-INF/web.xml";
	res = http_get_cache( item: url, port: port );
	if(res && egrep( string: res, pattern: base_pattern, icase: FALSE ) && egrep( string: res, pattern: extra_pattern, icase: FALSE )){
		continue;
	}
	url = str_replace( string: url, find: "/WEB-INF/web.xml", replace: "/%2557EB-INF/web.xml" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!res){
		continue;
	}
	if(egrep( string: res, pattern: base_pattern, icase: FALSE ) && egrep( string: res, pattern: extra_pattern, icase: FALSE )){
		report = http_report_vuln_url( port: port, url: url );
		report += "\nResponse (truncated):\n\n" + substr( res, 0, 1500 );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

