if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800154" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-4114" );
	script_bugtraq_id( 37044 );
	script_name( "Kaspersky Anti-Virus 2010 'kl1.sys' Driver DoS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37398" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54309" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/507933/100/0/threaded" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_kaspersky_av_detect.sc" );
	script_mandatory_keys( "Kaspersky/AV/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code with
  elevated privileges or cause the kernel to crash." );
	script_tag( name: "affected", value: "Kaspersky Anti-Virus 2010 before 9.0.0.736 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to NULL pointer dereference in 'kl1.sys' driver via a
  specially-crafted IOCTL 0x0022c008 call." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to version 9.0.0.736 or later." );
	script_tag( name: "summary", value: "The host is installed with Kaspersky Anti-Virus 2010 and is prone
  to Denial of Service vulnerability." );
	script_xref( name: "URL", value: "http://www.kaspersky.com/downloads" );
	exit( 0 );
}
require("version_func.inc.sc");
kavVer = get_kb_item( "Kaspersky/AV/Ver" );
if(kavVer != NULL){
	if(version_in_range( version: kavVer, test_version: "9.0", test_version2: "9.0.0.735" )){
		report = report_fixed_ver( installed_version: kavVer, vulnerable_range: "9.0 - 9.0.0.735" );
		security_message( port: 0, data: report );
	}
}

