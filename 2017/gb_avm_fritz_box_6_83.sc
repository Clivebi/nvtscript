CPE = "cpe:/o:avm:fritz%21_os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108146" );
	script_version( "$Revision: 11412 $" );
	script_name( "Multiple AVM FRITZ!Box VoIP Remote Code Execution" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-16 12:21:40 +0200 (Sun, 16 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2017-04-19 11:59:41 +0200 (Wed, 19 Apr 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_avm_fritz_box_detect.sc" );
	script_mandatory_keys( "avm/fritz/model", "avm/fritz/firmware_version" );
	script_xref( name: "URL", value: "https://www.heise.de/newsticker/meldung/Firmware-Status-von-AVM-Routern-checken-Kritisches-Sicherheitsloch-in-Fritzbox-Firmware-gestopft-3687437.html" );
	script_xref( name: "URL", value: "https://avm.de/service/aktuelle-sicherheitshinweise/" );
	script_tag( name: "vuldetect", value: "Check the firmware version." );
	script_tag( name: "solution", value: "Update the firmware to 6.83 or higher." );
	script_tag( name: "summary", value: "Several models of the AVM FRITZ!Box are vulnerable to a heap-based buffer overflow,
  which allows attackers to execute arbitrary code on the device." );
	script_tag( name: "affected", value: "AVM FRITZ!Box 7390, 7490 und 7580 with a firmware 6.80 or 6.81." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!fw_version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!model = get_kb_item( "avm/fritz/model" )){
	exit( 0 );
}
valid_models = make_list( "7390",
	 "7490",
	 "7580" );
for m in valid_models {
	if(egrep( string: model, pattern: "^" + m )){
		vuln_model = TRUE;
		break;
	}
}
if(!vuln_model){
	exit( 0 );
}
patch = "6.83";
if(!IsMatchRegexp( fw_version, "^6\\.8" )){
	exit( 99 );
}
if(version_is_less( version: fw_version, test_version: patch )){
	report = "Model:              " + model + "\n";
	report += "Installed Firmware: " + fw_version + "\n";
	report += "Fixed Firmware:     " + patch;
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

