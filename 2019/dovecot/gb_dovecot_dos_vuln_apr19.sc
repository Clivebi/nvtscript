if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113379" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-04-29 11:09:24 +0000 (Mon, 29 Apr 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-10691" );
	script_name( "Dovecot < 2.3.5.2 Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to a Denial of Service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The JSON encoder allows attackers to repeatedly crash the authentication
  service by attempting to authenticate with an invalid UTF-8 sequence as the username." );
	script_tag( name: "affected", value: "Dovecot version 2.3.0 through 2.3.5.1." );
	script_tag( name: "solution", value: "Update to version 2.3.5.2." );
	script_xref( name: "URL", value: "https://dovecot.org/list/dovecot-news/2019-April/000406.html" );
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
if(version_in_range( version: version, test_version: "2.3.0", test_version2: "2.3.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.5.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

