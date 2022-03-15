if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-March/msg00062.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870969" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-03-22 10:40:06 +0530 (Fri, 22 Mar 2013)" );
	script_cve_id( "CVE-2013-0254" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "RHSA", value: "2013:0669-01" );
	script_name( "RedHat Update for qt RHSA-2013:0669-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "qt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Qt is a software toolkit that simplifies the task of writing and
  maintaining GUI (Graphical User Interface) applications for the X Window
  System.

  It was discovered that the QSharedMemory class implementation of the Qt
  toolkit created shared memory segments with insecure permissions. A local
  attacker could use this flaw to read or alter the contents of a particular
  shared memory segment, possibly leading to their ability to obtain
  sensitive information or influence the behavior of a process that is using
  the shared memory segment. (CVE-2013-0254)

  Red Hat would like to thank the Qt project for reporting this issue.
  Upstream acknowledges Tim Brown and Mark Lowe of Portcullis Computer
  Security Ltd. as the original reporters.

  Users of Qt should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running applications linked
  against Qt libraries must be restarted for this update to take effect." );
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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "phonon-backend-gstreamer", rpm: "phonon-backend-gstreamer~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt", rpm: "qt~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-debuginfo", rpm: "qt-debuginfo~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-devel", rpm: "qt-devel~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-mysql", rpm: "qt-mysql~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-odbc", rpm: "qt-odbc~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-postgresql", rpm: "qt-postgresql~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-sqlite", rpm: "qt-sqlite~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-x11", rpm: "qt-x11~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qt-doc", rpm: "qt-doc~4.6.2~26.el6_4", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

