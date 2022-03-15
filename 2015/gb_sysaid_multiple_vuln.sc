CPE = "cpe:/a:sysaid:sysaid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106005" );
	script_version( "2020-04-23T05:44:42+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 05:44:42 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2993", "CVE-2015-2994", "CVE-2015-2998", "CVE-2015-2999", "CVE-2015-3000", "CVE-2015-3001" );
	script_name( "SysAid < 15.2 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sysaid_detect.sc" );
	script_mandatory_keys( "sysaid/detected" );
	script_tag( name: "summary", value: "SysAid Help Desktop Software is prone to multiple
  vulnerabilities" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "- SysAid Help Desktop Software does not properly restrict access
  to certain functionality. An attacker can create administrators accounts via crafted requests to
  /createnewaccount or write arbitrary files via the fileName parameter to /userentry. (CVE-2015-2993)

  - A vulnerability exists in the ChangePhoto.jsp in the administrator portal, which does not handle
    correctly directory traversal sequences and does not enforce file extension restrictions. (CVE-2015-2994)

  - SysAid Help Desktop Software uses a hard-coded encryption key. (CVE-2015-2998)

  - A SQL injection vulnerability exists in genericreport, HelpDesk.jsp and RFCGantt.jsp. (CVE-2015-2999)

  - An XML entity expansion vulnerability exists. CVE-2015-3000)

  - When installing SysAid on Windows with built in SQL-Server Express, the installer sets the sa user
    password to a pre-defined hard-coded password. (CVE-2015-3001)" );
	script_tag( name: "impact", value: "- An unauthenticated attacker can get full administrative access to
  the application or overwrite arbitrary files.

  - An authenticated attacker may upload arbitrary files which could lead to remote code execution.

  - A malicious user can decrypt e.g. the database password stored in serverConf.xml.

  - A user with administrative rights can perform a SQL injection attack to read and modify the database.

  - A unauthenticated attacker can create a Denial of Service condition for 10+ seconds. Repeating this
    will slow down the server extensively.

  - An attacker can gain administrative access to the built-in SQL Server Express." );
	script_tag( name: "affected", value: "SysAid Help Desktop version 15.1.x and before." );
	script_tag( name: "solution", value: "Upgrade to version 15.2 or later." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jun/8" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "15.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "15.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

