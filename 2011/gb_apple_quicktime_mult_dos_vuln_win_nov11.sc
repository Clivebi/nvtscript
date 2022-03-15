CPE = "cpe:/a:apple:quicktime";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802198" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2011-3219", "CVE-2011-3220", "CVE-2011-3221", "CVE-2011-3218", "CVE-2011-3222", "CVE-2011-3223", "CVE-2011-3228", "CVE-2011-3247", "CVE-2011-3248", "CVE-2011-3249", "CVE-2011-3250", "CVE-2011-3251", "CVE-2011-3428" );
	script_bugtraq_id( 50068, 50130, 50131, 50122, 50100, 50101, 50127, 50399, 50400, 50404, 50401, 50403 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)" );
	script_name( "Apple QuickTime Multiple Denial of Service Vulnerabilities - (Windows)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5016" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-11-314/" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-11-315/" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_quicktime_detection_win_900124.sc" );
	script_mandatory_keys( "QuickTime/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service via crafted files." );
	script_tag( name: "affected", value: "QuickTime Player version prior to 7.7.1." );
	script_tag( name: "insight", value: "The flaws are due to

  - A integer overflow while handling the PICT files and JPEG2000 encoded
    movie files.

  - A signedness issue existed in the handling of font tables embedded in
    QuickTime movie files.

  - A buffer overflow issue while handling FLIC files, FlashPix files and FLC
    and RLE encoded movie files.

  - A memory corruption issue, while handling of TKHD atoms in QuickTime
    movie files." );
	script_tag( name: "solution", value: "Upgrade to QuickTime Player version 7.7.1 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple QuickTime and is prone to multiple
  denial of service vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.7.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

