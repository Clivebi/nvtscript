if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105392" );
	script_cve_id( "CVE-2015-5435" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_version( "2020-04-01T10:41:43+0000" );
	script_name( "HP Integrated Lights-Out (iLO) 3 and 4 Remote Denial of Service" );
	script_tag( name: "last_modification", value: "2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2015-10-01 14:58:10 +0200 (Thu, 01 Oct 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "ilo_detect.sc" );
	script_mandatory_keys( "hp/ilo/detected" );
	script_xref( name: "URL", value: "http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04785857" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "See vendor advisory for a solution." );
	script_tag( name: "summary", value: "A potential security vulnerability has been identified with HP Integrated
  Lights-Out 3 and 4 (iLO 3, iLO 4). The vulnerability could be exploited remotely resulting in Denial of Service
  (DoS)." );
	script_tag( name: "affected", value: "HP Integrated Lights-Out 3 (iLO 3) prior to firmware version 1.85 HP
  Integrated Lights-Out 4 (iLO 4) prior to firmware version 2.22." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:hp:integrated_lights-out_3_firmware",
	 "cpe:/o:hp:integrated_lights-out_4_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!version = get_app_version( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
if( cpe == "cpe:/o:hp:integrated_lights-out_3_firmware" ){
	if(version_is_less( version: version, test_version: "1.85" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.85" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/o:hp:integrated_lights-out_4_firmware"){
		if(version_is_less( version: version, test_version: "2.22" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "2.22" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

