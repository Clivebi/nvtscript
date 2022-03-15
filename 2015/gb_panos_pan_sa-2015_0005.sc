CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105325" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_name( "Palo Alto PAN-OS PAN-SA-2015-0005" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/32" );
	script_tag( name: "summary", value: "Devices running PAN-OS 7.0.0 (including Panorama) that are configured to use LDAP for captive portal or device management authentication
do not properly perform authentication against the LDAP server in specific cases, leading to an authentication bypass. There is no issue if you are using Radius or local
authentication instead of LDAP or prior versions of PAN-OS. This does not affect authentication attempts from GlobalProtect clients either." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS 7.0.1" );
	script_tag( name: "impact", value: "This vulnerability can lead to authentication bypass for captive portal or device management login attempts." );
	script_tag( name: "affected", value: "PAN-OS 7.0.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-08-20 11:43:06 +0200 (Thu, 20 Aug 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version == "7.0.0"){
	fix = "7.0.1";
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

