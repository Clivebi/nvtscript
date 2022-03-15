if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-January/017241.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880466" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-31 15:15:14 +0100 (Mon, 31 Jan 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2011:0013" );
	script_cve_id( "CVE-2010-4538" );
	script_name( "CentOS Update for wireshark CESA-2011:0013 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "wireshark on CentOS 4" );
	script_tag( name: "insight", value: "Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  An array index error, leading to a stack-based buffer overflow, was found
  in the Wireshark ENTTEC dissector. If Wireshark read a malformed packet off
  a network or opened a malicious dump file, it could crash or, possibly,
  execute arbitrary code as the user running Wireshark. (CVE-2010-4538)

  Users of Wireshark should upgrade to these updated packages, which contain
  a backported patch to correct this issue. All running instances of
  Wireshark must be restarted for the update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.0.15~1.el4_8.3", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "wireshark-gnome", rpm: "wireshark-gnome~1.0.15~1.el4_8.3", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

