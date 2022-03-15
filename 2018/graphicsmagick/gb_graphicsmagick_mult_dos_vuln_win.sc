if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113137" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-15 14:01:02 +0100 (Thu, 15 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-10 16:15:00 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231" );
	script_name( "GraphicsMagick 1.3.26 Multiple DoS Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_graphicsmagick_detect_win.sc" );
	script_mandatory_keys( "GraphicsMagick/Win/Installed" );
	script_tag( name: "summary", value: "GraphicsMagick is prone to multiple Denial of Service vulnerabilities, exploitable via specially crafted files." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  An allocation failure vulnerability was found in the function ReadTIFFImage in coders/tiff.c, which allows attackers to cause a denial of service via a crafted file, because file size is not properly used to restrict scanline, strip, and tile allocations.

  A NULL pointer dereference vulnerability was found in the function ReadCINEONImage in coders/cineon.c, which allows attackers to cause a denial of service via a crafted file.

  A NULL pointer dereference vulnerability was found in the function ReadEnhMetaFile in coders/emf.c, which allows attackers to cause a denial of service via a crafted file." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash GraphicsMagick." );
	script_tag( name: "affected", value: "GraphicsMagick through version 1.3.26." );
	script_tag( name: "solution", value: "Update to version 1.3.27 or above." );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/461/" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/473/" );
	script_xref( name: "URL", value: "https://sourceforge.net/p/graphicsmagick/bugs/475/" );
	exit( 0 );
}
CPE = "cpe:/a:graphicsmagick:graphicsmagick";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.3.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.27", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

