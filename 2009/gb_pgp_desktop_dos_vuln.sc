if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800216" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2008-5731" );
	script_bugtraq_id( 32991 );
	script_name( "PGP Desktop Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33310" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7556" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_pgp_desktop_detect_win.sc" );
	script_mandatory_keys( "PGPDesktop/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary codes in
  the context of an application via crafted program to cause denial of service." );
	script_tag( name: "affected", value: "PGP Corporation, PGP Desktop version 9.9.0.397 or prior on Windows." );
	script_tag( name: "insight", value: "This flaw is due to an error in the PGPwded.sys device driver when handling
  certain METHOD_BUFFERED IOCTL request that overwrites portions of memory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to PGP Desktop version 9.10 or later." );
	script_tag( name: "summary", value: "This host is running PGP Desktop and is prone to Denial of Service
  Vulnerability." );
	script_xref( name: "URL", value: "http://www.pgp.com/products/desktop/index.html" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "PGPDesktop/Win/Ver" );
if(!ver){
	exit( 0 );
}
if(version_is_less_equal( version: ver, test_version: "9.9.0.397" )){
	report = report_fixed_ver( installed_version: ver, vulnerable_range: "Less than or equal to 9.9.0.397" );
	security_message( port: 0, data: report );
}

