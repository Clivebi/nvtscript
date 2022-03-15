CPE = "cpe:/a:phpmailer_project:phpmailer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809843" );
	script_version( "2020-12-29T14:18:00+0000" );
	script_cve_id( "CVE-2016-10045" );
	script_bugtraq_id( 95130 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-12-29 14:18:00 +0000 (Tue, 29 Dec 2020)" );
	script_tag( name: "creation_date", value: "2016-12-29 11:17:41 +0530 (Thu, 29 Dec 2016)" );
	script_name( "PHPMailer < 5.2.20 Remote Code Execution Vulnerability" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpmailer_detect.sc" );
	script_mandatory_keys( "phpmailer/detected" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40969" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Dec/81" );
	script_xref( name: "URL", value: "https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10045-Vuln-Patch-Bypass.html" );
	script_xref( name: "URL", value: "https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md" );
	script_tag( name: "summary", value: "This host is running PHPMailer and is prone
  to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to incomplete fix for
  CVE-2016-10033 as, PHPMailer uses the Sender variable to build the params
  string. The validation is done using the  RFC 3696 specification, which can
  allow emails to contain spaces when it has double quote." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows an
  remote attacker to execute arbitrary code in the context of the web server and
  compromise the target web application." );
	script_tag( name: "affected", value: "PHPMailer versions prior to 5.2.20" );
	script_tag( name: "solution", value: "Upgrade to PHPMailer 5.2.20 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "5.2.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.20", install_url: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

