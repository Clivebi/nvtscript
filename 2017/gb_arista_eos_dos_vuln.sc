CPE = "cpe:/o:arista:eos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106495" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-05 11:09:21 +0700 (Thu, 05 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)" );
	script_cve_id( "CVE-2016-6894" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Arista EOS DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_arista_eos_snmp_detect.sc" );
	script_mandatory_keys( "arista/eos/detected", "arista/eos/model" );
	script_tag( name: "summary", value: "Arista EOS on DCS-7050 series is prone to a denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "By sending crafted packets to the control plane it is possible to cause
  a denial of service condition (device reboot)." );
	script_tag( name: "affected", value: "Arista EOS 4.15.2F and later." );
	script_tag( name: "solution", value: "Upgrade to EOS version 4.15.8M, 4.16.7M, 4.17.0F or later." );
	script_xref( name: "URL", value: "https://www.arista.com/en/support/advisories-notices/security-advisories/1752-security-advisory-25" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "arista/eos/model" );
if(!IsMatchRegexp( model, "^DCS-7050(S|T|Q)" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.15.2F" )){
	exit( 99 );
}
if(version_is_less( version: version, test_version: "4.15.8M" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.15.8M" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.16" )){
	if(version_is_less( version: version, test_version: "4.16.7M" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.16.7M" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^4\\.17\\.0" )){
	if(version_is_less( version: version, test_version: "4.17.0F" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.17.0F" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

