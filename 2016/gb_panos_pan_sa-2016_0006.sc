CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105628" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 14181 $" );
	script_name( "Palo Alto PAN-OS PAN-SA-2016-0006" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/39" );
	script_tag( name: "summary", value: "An evasion was identified whereby a user could specially craft an HTTP header
  to evade URL filtering on Palo Alto Networks firewalls." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Customers concerned with this evasion technique are advised to upgrade to PAN-OS
  7.1.1 and to enable threat signatures #14984 and #14978." );
	script_tag( name: "impact", value: "The HTTP header evasion technique can be used by a malicious insider to bypass URL
  filtering policy. It is not a product vulnerability that affects the security or integrity of the firewall itself." );
	script_tag( name: "affected", value: "PAN-OS releases 5.0.X, 6.0.X, 6.1.X, 7.0.X and 7.1.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-29 12:00:28 +0200 (Fri, 29 Apr 2016)" );
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
if(version_in_range( version: version, test_version: "5.0", test_version2: "7.1.0" )){
	fix = "7.1.1";
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

