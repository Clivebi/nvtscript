if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112062" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-05 12:31:22 +0200 (Thu, 05 Oct 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-19 15:24:00 +0000 (Wed, 19 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-7666", "CVE-2017-7673", "CVE-2017-7680", "CVE-2017-7681", "CVE-2017-7683", "CVE-2017-7684", "CVE-2017-7685", "CVE-2017-7688" );
	script_bugtraq_id( 99586, 99587, 99592 );
	script_name( "Apache OpenMeetings < 3.3.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_openmeetings_detect.sc" );
	script_require_ports( "Services/www", 5080 );
	script_mandatory_keys( "Apache/Openmeetings/Installed" );
	script_tag( name: "summary", value: "Apache OpenMeetings < 3.3.0 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache OpenMeetings is prone to the following vulnerabilities:

  - Apache Openmeetings is vulnerable to Cross-Site Request Forgery (CSRF) attacks, XSS attacks, click-jacking, and MIME based attacks (CVE-2017-7666).

  - Apache OpenMeetings uses not very strong cryptographic storage, captcha is not used in registration and forget password dialogs and auth forms missing brute force protection (CVE-2017-7673).

  - Apache OpenMeetings has an overly permissive crossdomain.xml file. This allows for flash content to be loaded from untrusted domains (CVE-2017-7680).

  - Apache OpenMeetings is vulnerable to SQL injection. This allows authenticated users to modify the structure of the existing query
  and leak the structure of other queries being made by the application in the back-end (CVE-2017-7681).

  - Apache OpenMeetings displays Tomcat version and detailed error stack trace which is not secure (CVE.2017-7683).

  - Apache OpenMeetings doesn't check contents of files being uploaded. An attacker can cause a denial of service by uploading multiple large files to the server (CVE-2017-7684).

  - Apache OpenMeetingsrespond to the following insecure HTTP Methods: PUT, DELETE, HEAD, and PATCH (CVE-2017-7685).

  - Apache OpenMeetings updates user password in insecure manner." );
	script_tag( name: "affected", value: "Apache OpenMeetings prior to 3.3.0" );
	script_tag( name: "solution", value: "Update your software to version 3.3.0 to fix the issue" );
	script_xref( name: "URL", value: "https://openmeetings.apache.org/security.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe = "cpe:/a:apache:openmeetings";
if(!port = get_app_port( cpe: cpe )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "3.3.0" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.3.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

