if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103620" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Cisco DPC2420 Cross Site Scripting / File Disclosure" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118711/Cisco-DPC2420-Cross-Site-Scripting-File-Disclosure.html" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-12-10 11:09:30 +0100 (Mon, 10 Dec 2012)" );
	script_category( ACT_ATTACK );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Cisco DPC2420 router is prone to a file disclosure and to a XSS
  vulnerability because it fails to sufficiently sanitize user supplied data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/webstar.html";
if(http_vuln_check( port: port, url: url, pattern: "<TITLE>Cisco Cable Modem", usecache: TRUE )){
	url = "/filename.gwc";
	if(http_vuln_check( port: port, url: url, pattern: "Model Number", extra_check: make_list( "Serial Number",
		 "User Password" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

