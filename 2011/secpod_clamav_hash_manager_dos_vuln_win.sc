if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902726" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)" );
	script_cve_id( "CVE-2011-2721" );
	script_bugtraq_id( 48891 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "ClamAV Hash Manager Off-By-One Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45382" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68785" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2011/07/26/3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_clamav_detect_win.sc" );
	script_mandatory_keys( "ClamAV/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to provide a message with
  specially-crafted hash signature in it, leading to denial of service
  (clamscan executable crash)." );
	script_tag( name: "affected", value: "ClamAV version prior to 0.97.2 (3.0.3.6870) on Windows." );
	script_tag( name: "insight", value: "The flaw is due to the way the hash manager of Clam AntiVirus
  scans messages with certain hashes." );
	script_tag( name: "solution", value: "Upgrade to ClamAV 0.97.2 or later." );
	script_tag( name: "summary", value: "This host has ClamAV installed and is prone to denial of service
  vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.clamav.net/lang/en/" );
	exit( 0 );
}
require("version_func.inc.sc");
avVer = get_kb_item( "ClamAV/Win/Ver" );
if(!avVer){
	exit( 0 );
}
if(version_is_less( version: avVer, test_version: "0.97.2" )){
	report = report_fixed_ver( installed_version: avVer, fixed_version: "0.97.2" );
	security_message( port: 0, data: report );
}

