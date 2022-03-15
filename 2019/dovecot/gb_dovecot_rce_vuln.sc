CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142825" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-30 04:41:38 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-06 15:15:00 +0000 (Fri, 06 Sep 2019)" );
	script_cve_id( "CVE-2019-11500" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dovecot < 2.2.36.4 and < 2.3.7.2 Heap Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to an unauthenticated heap out of bounds heap memory write
  vulnerability." );
	script_tag( name: "insight", value: "This vulnerability allows for out-of-bounds writes to objects stored on the
  heap up to 8096 bytes in pre-login phase, and 65536 bytes post-login phase, allowing sufficiently skilled
  attacker to perform complicated attacks that can lead to leaking private information or remote code execution.
  Abuse of this bug is very difficult to observe, as it does not necessarily cause a crash. Attempts to abuse this
  bug are not directly evident from logs." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dovecot prior to version 2.2.36.4 and 2.3.x prior to version 2.3.7.2." );
	script_tag( name: "solution", value: "Update to version 2.2.36.4, 2.3.7.2 or later." );
	script_xref( name: "URL", value: "https://dovecot.org/pipermail/dovecot-news/2019-August/000418.html" );
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
if( version_is_less( version: version, test_version: "2.2.36.4" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.36.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: version, test_version: "2.3.0", test_version2: "2.3.7.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2.3.7.2", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

