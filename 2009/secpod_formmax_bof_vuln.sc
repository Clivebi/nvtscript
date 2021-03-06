if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900972" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3790" );
	script_name( "FormMax Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36943" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53890" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_formmax_detect.sc" );
	script_mandatory_keys( "FormMax/Evaluation/Ver" );
	script_tag( name: "impact", value: "Attackers can exploit this issue by executing arbitrary code in
the context of an affected application." );
	script_tag( name: "affected", value: "FormMax version 3.5 and prior" );
	script_tag( name: "insight", value: "The flaw is due to boundary error while processing malicious
'.aim' import files leading to heap-based buffer overflow." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with FormMax and is prone to Buffer
Overflow Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
fmVer = get_kb_item( "FormMax/Evaluation/Ver" );
if(!fmVer){
	exit( 0 );
}
if(version_is_less_equal( version: fmVer, test_version: "3.5" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

