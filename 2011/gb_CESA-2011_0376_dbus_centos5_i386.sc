if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017333.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880493" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0376" );
	script_cve_id( "CVE-2010-4352" );
	script_name( "CentOS Update for dbus CESA-2011:0376 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dbus'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "dbus on CentOS 5" );
	script_tag( name: "insight", value: "D-Bus is a system for sending messages between applications. It is used for
  the system-wide message bus service and as a per-user-login-session
  messaging facility.

  A denial of service flaw was discovered in the system for sending messages
  between applications. A local user could send a message with an excessive
  number of nested variants to the system-wide message bus, causing the
  message bus (and, consequently, any process using libdbus to receive
  messages) to abort. (CVE-2010-4352)

  All users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue. For the update to take effect, all
  running instances of dbus-daemon and all running applications using the
  libdbus library must be restarted, or the system rebooted." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "dbus", rpm: "dbus~1.1.2~15.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dbus-devel", rpm: "dbus-devel~1.1.2~15.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dbus-libs", rpm: "dbus-libs~1.1.2~15.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dbus-x11", rpm: "dbus-x11~1.1.2~15.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

