CPE = "cpe:/h:sony:sony_network_camera_snc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107106" );
	script_version( "$Revision: 11903 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-09 16:11:25 +0530 (Fri, 09 Dec 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Sony IPELA Engine IP Cameras Backdoor Vulnerability" );
	script_tag( name: "summary", value: "The host is running on a Sony IPELA Engine IP Camera
  and is prone to a backdoor vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of
  web requests passed via GET the parameter." );
	script_tag( name: "impact", value: "Successful exploitation may allows an attacker to run arbitrary code on the affected IP cameras." );
	script_tag( name: "affected", value: "According to Sony, at least the following products are affected:

  SNC-CH115, SNC-CH120, SNC-CH160, SNC-CH220, SNC-CH260, SNC-DH120,

  SNC-DH120T, SNC-DH160, SNC-DH220, SNC-DH220T, SNC-DH260, SNC-EB520,

  SNC-EM520, SNC-EM521, SNC-ZB550, SNC-ZM550, SNC-ZM551

  SNC-EP550, SNC-EP580, SNC-ER550, SNC-ER550C, SNC-ER580, SNC-ER585,

  SNC-ER585H, SNC-ZP550, SNC-ZR550

  SNC-EP520, SNC-EP521, SNC-ER520, SNC-ER521, SNC-ER521C

  SNC-CX600, SNC-CX600W, SNC-EB600, SNC-EB600B, SNC-EB602R, SNC-EB630,

  SNC-EB630B, SNC-EB632R, SNC-EM600, SNC-EM601, SNC-EM602R, SNC-EM602RC,

  SNC-EM630, SNC-EM631, SNC-EM632R, SNC-EM632RC, SNC-VB600, SNC-VB600B,

  SNC-VB600B5, SNC-VB630, SNC-VB6305, SNC-VB6307, SNC-VB632D, SNC-VB635,

  SNC-VM600, SNC-VM600B, SNC-VM600B5, SNC-VM601, SNC-VM601B, SNC-VM602R,

  SNC-VM630, SNC-VM6305, SNC-VM6307, SNC-VM631, SNC-VM632R, SNC-WR600,

  SNC-WR602, SNC-WR602C, SNC-WR630, SNC-WR632, SNC-WR632C, SNC-XM631,

  SNC-XM632, SNC-XM636, SNC-XM637, SNC-VB600L, SNC-VM600L, SNC-XM631L,

  SNC-WR602CL" );
	script_tag( name: "solution", value: "The vendor provided the following URL to download firmware updates for the affected devices. Updates should be installed immediately." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20161206-0_Sony_IPELA_Engine_IP_Cameras_Backdoors_v10.txt" );
	script_xref( name: "URL", value: "https://www.sony.co.uk/pro/article/sony-new-firmware-for-network-cameras" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_sony_ip_cam_detect.sc" );
	script_mandatory_keys( "sony/ip_camera/installed", "sony/ip_camera/model" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!sonycamPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!sonycamVer = get_app_version( cpe: CPE, port: sonycamPort )){
	exit( 0 );
}
if(!modelVer = get_kb_item( "sony/ip_camera/model" )){
	exit( 0 );
}
affected1 = make_list( "SNC-CH115",
	 "SNC-CH120",
	 "SNC-CH160",
	 "SNC-CH220",
	 "SNC-CH260",
	 "SNC-DH120",
	 "SNC-DH120T",
	 "SNC-DH160",
	 "SNC-DH220",
	 "SNC-DH220T",
	 "SNC-DH260",
	 "SNC-EB520",
	 "SNC-EM520",
	 "SNC-EM521",
	 "SNC-ZB550",
	 "SNC-ZM550",
	 "SNC-ZM551",
	 "SNC-EP550",
	 "SNC-EP580",
	 "SNC-ER550",
	 "SNC-ER550C",
	 "SNC-ER580",
	 "SNC-ER585",
	 "SNC-ER585H",
	 "SNC-ZP550",
	 "SNC-ZR550",
	 "SNC-EP520",
	 "SNC-EP521",
	 "SNC-ER520",
	 "SNC-ER521",
	 "SNC-ER521C" );
affected2 = make_list( "SNC-CX600",
	 "SNC-CX600W",
	 "SNC-EB600",
	 "SNC-EB600B",
	 "SNC-EB602R",
	 "SNC-EB630",
	 "SNC-EB630B",
	 "SNC-EB632R",
	 "SNC-EM600",
	 "SNC-EM601",
	 "SNC-EM602R",
	 "SNC-EM602RC",
	 "SNC-EM630",
	 "SNC-EM631",
	 "SNC-EM632R",
	 "SNC-EM632RC",
	 "SNC-VB600",
	 "SNC-VB600B",
	 "SNC-VB600B5",
	 "SNC-VB630",
	 "SNC-VB6305",
	 "SNC-VB6307",
	 "SNC-VB632D",
	 "SNC-VB635",
	 "SNC-VM600",
	 "SNC-VM600B",
	 "SNC-VM600B5",
	 "SNC-VM601",
	 "SNC-VM601B",
	 "SNC-VM602R",
	 "SNC-VM630",
	 "SNC-VM6305",
	 "SNC-VM6307",
	 "SNC-VM631",
	 "SNC-VM632R",
	 "SNC-WR600",
	 "SNC-WR602",
	 "SNC-WR602C",
	 "SNC-WR630",
	 "SNC-WR632",
	 "SNC-WR632C",
	 "SNC-XM631",
	 "SNC-XM632",
	 "SNC-XM636",
	 "SNC-XM637",
	 "SNC-VB600L",
	 "SNC-VM600L",
	 "SNC-XM631L",
	 "SNC-WR602CL" );
for v in affected1 {
	if(version_is_equal( version: modelVer, test_version: v )){
		if(version_is_less( version: sonycamVer, test_version: "1.86.00" )){
			report = report_fixed_ver( installed_version: modelVer + " Firmware v:" + sonycamVer, fixed_version: modelVer + " Firmware v:1.86.00" );
			security_message( data: report, port: sonycamPort );
			exit( 0 );
		}
	}
}
for v in affected2 {
	if(version_is_equal( version: modelVer, test_version: v )){
		if(version_is_less( version: sonycamVer, test_version: "2.7.2" )){
			report = report_fixed_ver( installed_version: modelVer + " Firmware v:" + sonycamVer, fixed_version: modelVer + " Firmware v:2.7.2" );
			security_message( data: report, port: sonycamPort );
			exit( 0 );
		}
	}
}
exit( 99 );

