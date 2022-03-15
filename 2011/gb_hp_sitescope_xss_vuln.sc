CPE = "cpe:/a:hp:sitescope";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801881" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)" );
	script_cve_id( "CVE-2011-1726", "CVE-2011-1727" );
	script_bugtraq_id( 47554 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hp_sitescope_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "hp/sitescope/installed" );
	script_xref( name: "URL", value: "https://secunia.com/advisories/44354" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/45958" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/1091" );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02807712" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker-supplied HTML and script code
  to run in the context of the affected browser, potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the user. Other attacks are also possible." );
	script_tag( name: "affected", value: "HP SiteScope versions 9.54, 10.13, 11.01, and 11.1" );
	script_tag( name: "insight", value: "The flaws are caused by input validation errors when processing
  user-supplied data, which could allow cross site scripting or HTML injection attacks." );
	script_tag( name: "solution", value: "Upgrade to HP SiteScope version 11.1 and apply the SS1110110412 hotfix." );
	script_tag( name: "summary", value: "This host is running HP SiteScope and is prone to cross site scripting
  and HTML injection vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/SiteScope/jsp/hosted/HostedSiteScopeMessage.jsp?messageKey=<script>alert('vt-xss-test')</script>" );
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "en.<script>alert\\('vt-xss-test'\\)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

