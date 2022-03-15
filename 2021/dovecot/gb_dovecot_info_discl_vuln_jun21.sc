CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117515" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-28 11:44:06 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 06:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_cve_id( "CVE-2021-33515" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dovecot 2.3.0 - 2.3.14 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "On-path attacker could inject plaintext commands before STARTTLS
  negotiation that would be executed after STARTTLS finished with the client. Only the SMTP
  submission service is affected." );
	script_tag( name: "impact", value: "Attacker can potentially steal user credentials and mails. The
  attacker needs to have sending permissions on the submission server (a valid username and password)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dovecot version 2.3.0 through- 2.3.14." );
	script_tag( name: "solution", value: "Update to version 2.3.14.1 or later." );
	script_xref( name: "URL", value: "https://dovecot.org/pipermail/dovecot-news/2021-June/000462.html" );
	script_xref( name: "URL", value: "https://dovecot.org/pipermail/dovecot-news/2021-June/000459.html" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "2.3.0", test_version2: "2.3.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.14.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

