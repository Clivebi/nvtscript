if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-January/015520.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880825" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0018" );
	script_cve_id( "CVE-2008-2383" );
	script_name( "CentOS Update for xterm CESA-2009:0018 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xterm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "xterm on CentOS 3" );
	script_tag( name: "insight", value: "The xterm program is a terminal emulator for the X Window System.

  A flaw was found in the xterm handling of Device Control Request Status
  String (DECRQSS) escape sequences. An attacker could create a malicious
  text file (or log entry, if unfiltered) that could run arbitrary commands
  if read by a victim inside an xterm window. (CVE-2008-2383)

  All xterm users are advised to upgrade to the updated package, which
  contains a backported patch to resolve this issue. All running instances of
  xterm must be restarted for the update to take effect." );
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
if(release == "CentOS3"){
	if(( res = isrpmvuln( pkg: "xterm", rpm: "xterm~179~11.EL3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

