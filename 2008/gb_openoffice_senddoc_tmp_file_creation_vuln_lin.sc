if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800129" );
	script_version( "$Revision: 12666 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-05 13:36:06 +0100 (Wed, 05 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2008-4937" );
	script_bugtraq_id( 30925 );
	script_name( "OpenOffice senddoc Insecure Temporary File Creation Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Remote file access" );
	script_dependencies( "secpod_openoffice_detect_lin.sc" );
	script_mandatory_keys( "OpenOffice/Linux/Ver" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2008/10/30/2" );
	script_xref( name: "URL", value: "http://dev.gentoo.org/~rbu/security/debiantemp/openoffice.org-common" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to delete or corrupt
  sensitive files, which may result in a denial of service condition." );
	script_tag( name: "affected", value: "OpenOffice.org 2.4.1 on Linux." );
	script_tag( name: "insight", value: "The flaw exists due to OpenOffice 'senddoc' which creates temporary files
  in an insecure manner, which allows users to overwrite files via a symlink
  attack on a /tmp/log.obr.##### temporary file." );
	script_tag( name: "solution", value: "Upgrade OpenOffice to higher version." );
	script_tag( name: "summary", value: "The host has OpenOffice installed and is prone to Insecure
  Temporary File Creation Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
vers = get_kb_item( "OpenOffice/Linux/Ver" );
if(!vers){
	exit( 0 );
}
if(vers == "2.4.1"){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
exit( 0 );

