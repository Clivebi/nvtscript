CPE = "cpe:/a:pivotx:pivotx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801735" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)" );
	script_cve_id( "CVE-2011-0772" );
	script_bugtraq_id( 45996 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "PivotX Multiple Cross-site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pivotx_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "PivotX/Installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43040" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64975" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "PivotX version prior to 2.3.2." );
	script_tag( name: "insight", value: "The flaws are due to input passed to the 'color' parameter in 'pivotx/includes/blogroll.php',
  'src' parameter in 'pivotx/includes/timwrapper.php' is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "Update to PivotX version 2.3.2 or later." );
	script_tag( name: "summary", value: "This host is running PivotX and is prone to multiple
  Cross-site Scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
url = dir + "/pivotx/includes/timwrapper.php?src=\"><script>alert(\"VT-XSS-Test\");</script>";
if(http_vuln_check( port: port, url: url, pattern: "><script>alert(\"VT-XSS-Test\");</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

