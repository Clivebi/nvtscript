if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142106" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-08 11:46:17 +0700 (Fri, 08 Mar 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-20 19:29:00 +0000 (Thu, 20 Dec 2018)" );
	script_cve_id( "CVE-2018-14695", "CVE-2018-14696", "CVE-2018-14700", "CVE-2018-14703", "CVE-2018-14704" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Drobo NAS Multiple Vulnerabilities in MySQL Web Application" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_drobo_nas_consolidation.sc" );
	script_mandatory_keys( "drobo/mysqlapp/detected" );
	script_tag( name: "summary", value: "Drobo NAS are prone to multiple vulnerabilities in their MySQL Web
Application." );
	script_tag( name: "insight", value: "Drobo NAS are prone to multiple vulnerabilities in their MySQL Web
Application:

  - Unauthenticated Access to MySQL diag.php (CVE-2018-14695)

  - Unauthenticated Access to device info via MySQL API drobo.php (CVE-2018-14696)

  - Unauthenticated Access to MySQL Log Files (CVE-2018-14700)

  - Unauthenticated Access to MySQL Database Password (CVE-2018-14703)

  - Reflected Cross-Site Scripting via MySQL API droboapps.php (CVE-2018-14704)" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Tries to obtain the root password for MySQL." );
	script_xref( name: "URL", value: "https://blog.securityevaluators.com/call-me-a-doctor-new-vulnerabilities-in-drobo5n2-4f1d885df7fc" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_kb_item( "drobo/mysqlapp/port" )){
	exit( 0 );
}
url = "/mysql/api/droboapp/data";
if(http_vuln_check( port: port, url: url, pattern: "\"password\":\"[0-9a-f]+", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

