CPE = "cpe:/a:emc:rsa_archer_grc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106919" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-03 16:15:11 +0700 (Mon, 03 Jul 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-17 18:06:00 +0000 (Mon, 17 Jul 2017)" );
	script_cve_id( "CVE-2017-4998", "CVE-2017-4999", "CVE-2017-5000", "CVE-2017-5001", "CVE-2017-5002" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "RSA Archer Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_rsa_archer_detect.sc" );
	script_mandatory_keys( "rsa_archer/installed" );
	script_tag( name: "summary", value: "RSA Archer is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "RSA Archer is prone to multiple vulnerabilities:

  - Cross-Site Request Forgery Vulnerability (CVE-2017-4998)

  - Authorization Bypass Through User-Controlled Key Vulnerability (CVE-2017-4999)

  - Information Disclosure Vulnerability (CVE-2017-5000)

  - Cross Site Scripting Vulnerability (CVE-2017-5001)

  - Open Redirect Vulnerability (CVE-2017-5002)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to RSA Archer GRC 6.2.0.2 or later." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Jun/49" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.2.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.0.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

