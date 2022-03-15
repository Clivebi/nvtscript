CPE = "cpe:/a:tigervnc:tigervnc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801898" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_cve_id( "CVE-2011-1775" );
	script_bugtraq_id( 47738 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "TigerVNC SSL Certificate Validation Security Bypass Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=702470" );
	script_xref( name: "URL", value: "http://www.mail-archive.com/tigervnc-devel@lists.sourceforge.net/msg01345.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_tigervnc_detect_win.sc" );
	script_mandatory_keys( "TigerVNC6432/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to perform
man-in-the-middle attacks or impersonate trusted servers, which will aid in
further attacks." );
	script_tag( name: "affected", value: "TigerVNC version 1.1beta1" );
	script_tag( name: "insight", value: "The flaw is caused by improper verification of server's X.509
certificate, which allows man-in-the-middle attackers to spoof a TLS VNC server
via an arbitrary certificate." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with TigerVNC and is prone to security
bypass vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
ver = get_app_version( cpe: CPE );
if(ver){
	if(version_is_equal( version: ver, test_version: "1.0.90" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

