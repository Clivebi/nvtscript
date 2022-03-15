if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106571" );
	script_version( "2020-06-08T14:13:59+0000" );
	script_tag( name: "last_modification", value: "2020-06-08 14:13:59 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_cve_id( "CVE-2015-1460" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Quidway Switches Privilege Escalation Vulnerability (huawei-sa-20150121-01-quidway)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Huawei Quidway switches are prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Huawei Quidway switches allows remote attackers to gain privileges via a
  crafted packet." );
	script_tag( name: "impact", value: "Attackers may exploit this vulnerability to obtain higher access
  permissions." );
	script_tag( name: "affected", value: "Quidway S2350, S2750, S5300, S5700, S6300, S6700, S7700, S9300, S9300E and
  S9700 with versions prior to V200R005C00SPC300." );
	script_tag( name: "solution", value: "Upgrade to Version V200R005C00SPC300 or later." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/hw-411975" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:s2350_firmware",
	 "cpe:/o:huawei:s2750_firmware",
	 "cpe:/o:huawei:s5300_firmware",
	 "cpe:/o:huawei:s5700_firmware",
	 "cpe:/o:huawei:s6300_firmware",
	 "cpe:/o:huawei:s6700_firmware",
	 "cpe:/o:huawei:s7700_firmware",
	 "cpe:/o:huawei:s9300_firmware",
	 "cpe:/o:huawei:s9300e_firmware",
	 "cpe:/o:huawei:sS9700_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
if(!version = get_app_version( cpe: cpe, nofork: TRUE )){
	exit( 0 );
}
version = toupper( version );
if(revcomp( a: version, b: "V200R005C00SPC300" ) < 0){
	report = report_fixed_ver( installed_version: version, fixed_version: "V200R005C00SPC300" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

