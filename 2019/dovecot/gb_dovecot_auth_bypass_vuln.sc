if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112510" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-07 10:10:10 +0100 (Thu, 07 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-3814" );
	script_name( "Dovecot 1.1.0 - 2.2.36 and 2.3.0 - 2.3.4 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "If the provided trusted SSL certificate is missing the username field,
  Dovecot should be failing the authentication. However, the earlier versions will take the username from
  the user provided authentication fields (e.g. LOGIN command)." );
	script_tag( name: "impact", value: "If there is no additional password verification, this allows the attacker
  to login as anyone else in the system." );
	script_tag( name: "affected", value: "Dovecot versions 1.1.0 through 2.2.36 and 2.3.0 through 2.3.4." );
	script_tag( name: "solution", value: "Update to version 2.2.36.1 or 2.3.4.1 respectively." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2019/02/05/1" );
	exit( 0 );
}
CPE = "cpe:/a:dovecot:dovecot";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if( version_in_range( version: version, test_version: "1.1.0", test_version2: "2.2.36" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.36.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: version, test_version: "2.3.0", test_version2: "2.3.4" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.3.4.1", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

