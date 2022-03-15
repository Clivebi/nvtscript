if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900540" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0792", "CVE-2009-0196" );
	script_bugtraq_id( 34445, 34184 );
	script_name( "Ghostscript Multiple Buffer Overflow Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34292" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0983" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Apr/1022029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_ghostscript_detect_win.sc" );
	script_mandatory_keys( "artifex/ghostscript/win/detected" );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker to execute arbitrary code in
  the context of the affected application and can cause denial of service." );
	script_tag( name: "affected", value: "Ghostscript version 8.64 and prior on Windows." );
	script_tag( name: "insight", value: "These flaws arise due to:

  - a boundary error in the jbig2_symbol_dict.c() function in the JBIG2
    decoding library (jbig2dec) while decoding JBIG2 symbol dictionary
    segments.

  - multiple integer overflows in icc.c in the ICC Format library while
    processing malformed PDF and PostScript files with embedded images." );
	script_tag( name: "solution", value: "Upgrade to Ghostscript version 8.71 or later." );
	script_tag( name: "summary", value: "This host is installed with Ghostscript and is prone to
  Buffer Overflow Vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://ghostscript.com/releases/" );
	exit( 0 );
}
CPE = "cpe:/a:artifex:ghostscript";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "8.64" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.71", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

