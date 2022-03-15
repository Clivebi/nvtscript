if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801125" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3662" );
	script_bugtraq_id( 36397 );
	script_name( "FileCopa FTP Server 'NOOP' Command DoS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36773" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/36397.txt" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "gb_filecopa_ftp_server_detect.sc" );
	script_mandatory_keys( "FileCOPA-FTP-Server/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a Denial of Service." );
	script_tag( name: "affected", value: "FileCopa FTP Server version 5.01 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in the handling of 'NOOP' FTP commands.
  This can be exploited to hang an affected server via an overly large number
  of specially crafted NOOP commands." );
	script_tag( name: "solution", value: "Upgrade to FileCopa FTP Server version 5.02." );
	script_tag( name: "summary", value: "This host is running FileCopa FTP Server and is prone to Denial of
  Service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("version_func.inc.sc");
filecopaVer = get_kb_item( "FileCOPA-FTP-Server/Ver" );
if(!filecopaVer){
	exit( 0 );
}
if(version_is_less( version: filecopaVer, test_version: "5.02" )){
	report = report_fixed_ver( installed_version: filecopaVer, fixed_version: "5.02" );
	security_message( port: 0, data: report );
}

