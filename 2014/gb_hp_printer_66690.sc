if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105040" );
	script_bugtraq_id( 66690 );
	script_cve_id( "CVE-2014-0160" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_name( "HP Officejet Pro X Printers, Certain Officejet Pro Printers, Remote Disclosure of Information" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/531993" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-06-03 16:01:41 +0200 (Tue, 03 Jun 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_hp_printer_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "hp_fw_ver", "hp_model" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to gain access to sensitive
  information that may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Check the firmware version." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "A potential security vulnerability has been identified in HP Officejet
  Pro X printers and in certain Officejet Pro printers running OpenSSL. This is the OpenSSL
  vulnerability known as 'Heartbleed' (CVE-2014-0160) which could be exploited remotely
  resulting in disclosure of information." );
	script_tag( name: "affected", value: "HP Officejet Pro X451dn < BNP1CN1409BR

HP Officejet Pro X451dw  < BWP1CN1409BR

HP Officejet Pro X551dw  < BZP1CN1409BR

HP Officejet Pro X476dn  < LNP1CN1409BR

HP Officejet Pro X476dw  < LWP1CN1409BR

HP Officejet Pro X576dw  < LZP1CN1409BR

HP Officejet Pro 276dw   < FRP1CN1416BR

HP Officejet Pro 251dw   < EVP1CN1416BR

HP Officejet Pro 8610    < FDP1CN1416AR

HP Officejet Pro 8615    < FDP1CN1416AR

HP Officejet Pro 8620    < FDP1CN1416AR

HP Officejet Pro 8625    < FDP1CN1416AR

HP Officejet Pro 8630    < FDP1CN1416AR

HP Officejet Pro 8640    < FDP1CN1416AR

HP Officejet Pro 8660    < FDP1CN1416AR" );
	exit( 0 );
}
require("host_details.inc.sc");
port = get_kb_item( "hp_printer/port" );
if(!port){
	port = 0;
}
fw_ver = get_kb_item( "hp_fw_ver" );
if(!fw_ver){
	exit( 0 );
}
model = get_kb_item( "hp_model" );
if(!model){
	exit( 0 );
}
if( ContainsString( model, "Officejet Pro X451dn" ) ) {
	fixed_ver = "BNP1CN1409BR";
}
else {
	if( ContainsString( model, "Officejet Pro X451dw" ) ) {
		fixed_ver = "BWP1CN1409BR";
	}
	else {
		if( ContainsString( model, "Officejet Pro X551dw" ) ) {
			fixed_ver = "BZP1CN1409BR";
		}
		else {
			if( ContainsString( model, "Officejet Pro X476dn" ) ) {
				fixed_ver = "LNP1CN1409BR";
			}
			else {
				if( ContainsString( model, "Officejet Pro X476dw" ) ) {
					fixed_ver = "LWP1CN1409BR";
				}
				else {
					if( ContainsString( model, "Officejet Pro X576dw" ) ) {
						fixed_ver = "LZP1CN1409BR";
					}
					else {
						if( ContainsString( model, "Officejet Pro 276dw" ) ) {
							fixed_ver = "FRP1CN1416BR";
						}
						else {
							if( ContainsString( model, "Officejet Pro 251dw" ) ) {
								fixed_ver = "EVP1CN1416BR";
							}
							else {
								if( ContainsString( model, "Officejet Pro 8610" ) ) {
									fixed_ver = "FDP1CN1416AR";
								}
								else {
									if( ContainsString( model, "Officejet Pro 8615" ) ) {
										fixed_ver = "FDP1CN1416AR";
									}
									else {
										if( ContainsString( model, "Officejet Pro 8620" ) ) {
											fixed_ver = "FDP1CN1416AR";
										}
										else {
											if( ContainsString( model, "Officejet Pro 8625" ) ) {
												fixed_ver = "FDP1CN1416AR";
											}
											else {
												if( ContainsString( model, "Officejet Pro 8630" ) ) {
													fixed_ver = "FDP1CN1416AR";
												}
												else {
													if( ContainsString( model, "Officejet Pro 8640" ) ) {
														fixed_ver = "FDP1CN1416AR";
													}
													else {
														if(ContainsString( model, "Officejet Pro 8660" )){
															fixed_ver = "FDP1CN1416AR";
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
if(!fixed_ver){
	exit( 0 );
}
fw_build = int( substr( fw_ver, 6, 9 ) );
fixed_build = int( substr( fixed_ver, 6, 9 ) );
if(fw_build < fixed_build){
	report = "Detected Firmware: " + fw_ver + "\nFixed Firmware:    " + fixed_ver + "\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

