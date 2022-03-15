if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900538" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1301" );
	script_bugtraq_id( 34381 );
	script_name( "mpg123 Player Denial of Service Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34587" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0936" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_mpg123_detect_lin.sc" );
	script_mandatory_keys( "mpg123/Linux/Ver" );
	script_tag( name: "affected", value: "mpg123 Player prior to 1.7.2 on Linux." );
	script_tag( name: "insight", value: "This flaw is due to integer signedness error in the store_id3_text function
  in the ID3v2 code when processing ID3v2 tags with negative encoding values." );
	script_tag( name: "solution", value: "Update to version 1.7.2." );
	script_tag( name: "summary", value: "This host is running mpg123 Player which is prone to denial of
  service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker trigger out of bounds
  memory access and thus execute arbitrary code and possibly crash the
  application." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
mpgVer = get_kb_item( "mpg123/Linux/Ver" );
if(!mpgVer){
	exit( 0 );
}
if(version_is_less( version: mpgVer, test_version: "1.7.2" )){
	report = report_fixed_ver( installed_version: mpgVer, fixed_version: "1.7.2" );
	security_message( port: 0, data: report );
}

