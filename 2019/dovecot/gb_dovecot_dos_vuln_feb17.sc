CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114166" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-12-16 12:43:21 +0100 (Mon, 16 Dec 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-02-22 19:11:00 +0000 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-8652" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dovecot < 2.2.27.1rc1 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to a Denial of Service vulnerability." );
	script_tag( name: "insight", value: "The Dovecot auth component can be crashed by a remote user
  when auth-policy is activated. That remote user can then use SASL authentication to crash
  the auth component." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dovecot between 2.2.25.1 and 2.2.26.1." );
	script_tag( name: "solution", value: "Update to version 2.2.27.1rc1 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2016/12/02/4" );
	exit( 0 );
}
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
if(version_in_range( version: version, test_version: "2.2.25.1", test_version2: "2.2.26.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.27.1rc1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

