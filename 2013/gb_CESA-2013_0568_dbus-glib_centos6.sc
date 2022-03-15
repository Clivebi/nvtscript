if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019617.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881631" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-12 09:58:45 +0530 (Tue, 12 Mar 2013)" );
	script_cve_id( "CVE-2013-0292" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2013:0568" );
	script_name( "CentOS Update for dbus-glib CESA-2013:0568 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dbus-glib'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "dbus-glib on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "dbus-glib is an add-on library to integrate the standard D-Bus library with
  the GLib main loop and threading model.

  A flaw was found in the way dbus-glib filtered the message sender (message
  source subject) when the 'NameOwnerChanged' signal was received. This
  could trick a system service using dbus-glib (such as fprintd) into
  believing a signal was sent from a privileged process, when it was not. A
  local attacker could use this flaw to escalate their privileges.
  (CVE-2013-0292)

  All dbus-glib users are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running applications
  linked against dbus-glib, such as fprintd and NetworkManager, must be
  restarted for this update to take effect." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "dbus-glib", rpm: "dbus-glib~0.86~6.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dbus-glib-devel", rpm: "dbus-glib-devel~0.86~6.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

