if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113334" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-13 10:50:14 +0200 (Wed, 13 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-12 13:57:00 +0000 (Tue, 12 Feb 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2019-7544", "CVE-2019-7730", "CVE-2019-7731" );
	script_name( "MyWebSQL <= 3.8 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mywebsql_http_detect.sc" );
	script_mandatory_keys( "mywebsql/detected" );
	script_tag( name: "summary", value: "MyWebSQL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - The Add User function of the User Manager pages has a
    Stored Cross-Site Scripting (XSS) vulnerability in the User Name Field

  - Cross-Site Request Forgery (CSRF) for deleting a database
    via the /?q=wrkfrm&type=databases URI

  - Remote Code Execution (RCE) vulnerability after an attacker writes shell
    code into the database, and executes the Backup Database function with
    a .php filename for the backup's archive file" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary code
  on the target machine." );
	script_tag( name: "affected", value: "MyWebSQL through version 3.8." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/eddietcc/CVEnotes/blob/master/MyWebSQL/CSRF/readme.md" );
	script_xref( name: "URL", value: "https://github.com/eddietcc/CVEnotes/blob/master/MyWebSQL/RCE/readme.md" );
	script_xref( name: "URL", value: "https://github.com/0xUhaw/CVE-Bins/blob/master/MyWebSQL/Readme.md" );
	exit( 0 );
}
CPE = "cpe:/a:mywebsql:mywebsql";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "3.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

