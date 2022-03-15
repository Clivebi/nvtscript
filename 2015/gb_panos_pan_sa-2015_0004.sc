CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105324" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "$Revision: 12106 $" );
	script_name( "Palo Alto PAN-OS PAN-SA-2015-0004" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/31" );
	script_tag( name: "impact", value: "This issue affects the management interface of the device, where an authenticated administrator injects malicious XML data into the web UI interface." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS 6.1.4, PAN-OS 6.0.8, or PAN-OS 5.0.16" );
	script_tag( name: "summary", value: "An XML parsing vulnerability exists in PAN-OS allowing a malicious user within PAN-OS to inject malicious
XML data into the web-based device management front-end allowing the user to retrieve arbitrary content from the device. The user must be an
authenticated user issuing the request. (Ref #71273)" );
	script_tag( name: "affected", value: "PAN-OS 6.1.3 and earlier, PAN-OS 6.0.7 and earlier, PAN-OS 5.0.15 and earlier" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-20 11:43:06 +0200 (Thu, 20 Aug 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
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
if( version_is_less_equal( version: version, test_version: "5.0.15" ) ) {
	fix = "5.0.16";
}
else {
	if( version_in_range( version: version, test_version: "6.0", test_version2: "6.0.7" ) ) {
		fix = "6.0.8";
	}
	else {
		if(version_in_range( version: version, test_version: "6.1", test_version2: "6.1.3" )){
			fix = "6.1.4";
		}
	}
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

