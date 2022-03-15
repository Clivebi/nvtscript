CPE = "cpe:/o:d-link:dir-816l_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144346" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-04 02:12:24 +0000 (Tue, 04 Aug 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-24 20:08:00 +0000 (Fri, 24 Jul 2020)" );
	script_cve_id( "CVE-2020-15893", "CVE-2020-15894", "CVE-2020-15895" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "D-Link DIR-816L <= 2.06.B09 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dir_device" );
	script_tag( name: "summary", value: "D-Link DIR-816L is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Command injection in the UPnP via a crafted M-SEARCH packet (CVE-2020-15893)

  - Exposed administration function, allowing unauthorized access to the few sensitive information (CVE-2020-15894)

  - Reflected XSS due to an unescaped value on the device configuration webpage (CVE-2020-15895)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "D-Link DIR-816L version 2.06.B09 and prior." );
	script_tag( name: "solution", value: "No solution was made available by the vendor. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.
  The vendor states: DIR-816L (EOS: 03/01/2016) have reached its End-of-Support ('EOS') / End-of-Life ('EOL') Date.
  As a general policy, when the product reaches EOS/EOL, it can no longer be supported, and all firmware
  development for the product ceases, except in certain unique situations." );
	script_xref( name: "URL", value: "https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10169" );
	script_xref( name: "URL", value: "https://research.loginsoft.com/vulnerability/multiple-vulnerabilities-discovered-in-the-d-link-firmware-dir-816l/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.06.B09" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

