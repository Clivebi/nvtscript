if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881788" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-09-06 09:37:00 +0530 (Fri, 06 Sep 2013)" );
	script_cve_id( "CVE-2013-4169" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for gdm CESA-2013:1213 centos5" );
	script_tag( name: "affected", value: "gdm on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The GNOME Display Manager (GDM) provides the graphical login screen, shown
shortly after boot up, log out, and when user-switching.

A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged user
could use this flaw to perform a symbolic link attack, giving them write
access to any file, allowing them to escalate their privileges to root.
(CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the initscripts
package was modified to create the affected directory safely during the
system boot process. Therefore, this update will appear on all systems,
however systems without GDM installed are not affected by this flaw.

Red Hat would like to thank the researcher with the nickname vladz for
reporting this issue.

All users should upgrade to these updated packages, which correct this
issue. The system must be rebooted for this update to take effect." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1213" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-September/019925.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "gdm", rpm: "gdm~2.16.0~59.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gdm-docs", rpm: "gdm-docs~2.16.0~59.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

