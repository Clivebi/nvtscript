if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902548" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)" );
	script_cve_id( "CVE-2011-1033" );
	script_bugtraq_id( 46230 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "IBM Informix Dynamic Server Oninit Remote Code Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43212" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65209" );
	script_xref( name: "URL", value: "http://zerodayinitiative.com/advisories/ZDI-11-050/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_ibm_informix_dynamic_server_detect_lin.sc" );
	script_mandatory_keys( "IBM/Informix/Dynamic/Server/Lin/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges." );
	script_tag( name: "affected", value: "IBM Informix Dynamic Server (IDS) version 11.50" );
	script_tag( name: "insight", value: "The flaw is due to a boundary error in the oninit process bound to TCP
  port 9088 when processing the arguments to the USELASTCOMMITTED option in a
  SQL query." );
	script_tag( name: "solution", value: "Upgrade to IBM Informix IDS version 11.50.xC8 or later." );
	script_tag( name: "summary", value: "This host is installed with IBM Informix Dynamic Server and is
  prone to remote code execution vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "IBM/Informix/Dynamic/Server/Lin/Ver" );
if(version){
	if(version_is_equal( version: version, test_version: "11.50" )){
		report = report_fixed_ver( installed_version: version, vulnerable_range: "Equal to 11.50" );
		security_message( port: 0, data: report );
	}
}

