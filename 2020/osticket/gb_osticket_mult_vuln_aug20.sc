CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144509" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-08-31 06:10:51 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:29:00 +0000 (Sat, 30 Jan 2021)" );
	script_cve_id( "CVE-2020-16193", "CVE-2020-24917", "CVE-2020-24881" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "osTicket < 1.14.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "summary", value: "osTicket is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - XSS because include/staff/banrule.inc.php has an unvalidated echo $info['notes'] call (CVE-2020-16193)

  - XSS via a crafted filename to DraftAjaxAPI::_uploadInlineImage() in include/ajax.draft.php (CVE-2020-24917)

  - SSRF where an attacker can add malicious file to server or perform port scanning (CVE-2020-24881)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "osTicket version 1.14.2 and prior." );
	script_tag( name: "solution", value: "Update to version 1.14.3 or later." );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/pull/5616/commits/fb570820ef1138776f929a179906e1d8089179d9" );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/commit/518de223933eab0c5558741ce317f36958ef193d" );
	script_xref( name: "URL", value: "https://sisl.lab.uic.edu/projects/chess/osticket-xss/" );
	script_xref( name: "URL", value: "https://blackbatsec.medium.com/cve-2020-24881-server-side-request-forgery-in-osticket-eea175e147f0" );
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
if(version_is_less( version: version, test_version: "1.14.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.14.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

