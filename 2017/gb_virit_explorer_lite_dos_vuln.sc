CPE = "cpe:/a:tg_soft:vir.it_explorer_lite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107266" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2017-16948" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-15 19:16:00 +0000 (Fri, 15 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-11-27 09:50:38 +0700 (Mon, 27 Nov 2017)" );
	script_name( "TG Soft Vir.IT eXplorer Lite Denial Of Service Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with TG Soft Vir.IT eXplorer Lite and is prone to
Denial Of Service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a NULL value in a 0x82730008 DeviceIoControl request to
\\\\\\\\.\\\\Viragtlt." );
	script_tag( name: "impact", value: "Successful exploitation would allow local users to cause a denial of service
(NULL pointer dereference) or possibly have unspecified other impact." );
	script_tag( name: "affected", value: "TG Soft Vir.IT eXplorer Lite 8.5.42" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://vuldb.com/en/?id.109971" );
	script_xref( name: "URL", value: "https://github.com/k0keoyo/Vir.IT-explorer-Anti-Virus-Null-Pointer-Reference-PoC/tree/master/VirIT_NullPointerReference1" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_virit_explorer_lite_detect.sc" );
	script_mandatory_keys( "Virit/explorer/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: Ver, test_version: "8.5.42" )){
	report = report_fixed_ver( installed_version: Ver, fixed_version: "None" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

