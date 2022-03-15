if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900429" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 33249 );
	script_cve_id( "CVE-2009-0122" );
	script_name( "HP Linux Imaging and Printing System Security Bypass Vulnerability" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "secpod_hplip_detect_lin.sc" );
	script_mandatory_keys( "HP-LIP/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker gain unauthorized privileges
  and escalate the privileges in a malicious way." );
	script_tag( name: "affected", value: "HP Linux Imaging and Printing System version 2.7.7 or 2.8.2" );
	script_tag( name: "insight", value: "This flaw is due to the 'postinst' script of the hplip package which tries
  to change the permissions of user config files in an insecure manner." );
	script_tag( name: "summary", value: "This host is installed with HP Linux Imaging and Printing System
  and is prone to Security Bypass vulnerability." );
	script_tag( name: "solution", value: "Upgrade to a later version." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33539" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-708-1" );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/ubuntu/+source/hplip/+bug/191299" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
hplipVer = get_kb_item( "HP-LIP/Linux/Ver" );
if(!hplipVer){
	exit( 0 );
}
if(IsMatchRegexp( hplipVer, "(2\\.7\\.7|2\\.8\\.2)" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

