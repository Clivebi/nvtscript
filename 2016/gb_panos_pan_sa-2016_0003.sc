CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105563" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12096 $" );
	script_cve_id( "CVE-2016-3655" );
	script_name( "Palo Alto PAN-OS PAN-SA-2016-0003" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/36" );
	script_tag( name: "summary", value: "Palo Alto Networks PAN-OS implements an API to enable programmatic device configuration and administration of the device. An issue was identified where the management API incorrectly parses input to a specific API call, leading to execution of arbitrary OS commands without authentication via the management interface." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS releases 5.0.18, 6.0.13, 6.1.10 and 7.0.5 and newer" );
	script_tag( name: "impact", value: "This issue can be exploited remotely by an unauthenticated user with network access to the device management web-based API" );
	script_tag( name: "affected", value: "PAN-OS releases 5.0.17, 6.0.12, 6.1.9, 7.0.4 and prior" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-25 13:50:51 +0100 (Thu, 25 Feb 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.0.17" )){
	fix = "5.0.18";
}
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.12" )){
	fix = "6.0.13";
}
if(version_in_range( version: version, test_version: "6.1", test_version2: "6.1.9" )){
	fix = "6.1.10";
}
if(version_in_range( version: version, test_version: "7.0", test_version2: "7.0.4" )){
	fix = "7.0.5";
}
if(fix){
	report = "Installed version: " + version + "\n" + "Fixed version:     " + fix;
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

