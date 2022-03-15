if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871104" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-12-23 12:38:28 +0530 (Mon, 23 Dec 2013)" );
	script_cve_id( "CVE-2013-6424" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "RedHat Update for xorg-x11-server RHSA-2013:1868-01" );
	script_tag( name: "affected", value: "xorg-x11-server on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "X.Org is an open source implementation of the X Window System. It provides
the basic low-level functionality that full-fledged graphical user
interfaces are designed upon.

An integer overflow, which led to a heap-based buffer overflow, was found
in the way X.Org server handled trapezoids. A malicious, authorized client
could use this flaw to crash the X.Org server or, potentially, execute
arbitrary code with root privileges. (CVE-2013-6424)

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2013:1868-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-December/msg00043.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(6|5)" );
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
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xephyr", rpm: "xorg-x11-server-Xephyr~1.13.0~23.1.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xorg", rpm: "xorg-x11-server-Xorg~1.13.0~23.1.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-common", rpm: "xorg-x11-server-common~1.13.0~23.1.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-debuginfo", rpm: "xorg-x11-server-debuginfo~1.13.0~23.1.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xdmx", rpm: "xorg-x11-server-Xdmx~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xephyr", rpm: "xorg-x11-server-Xephyr~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xnest", rpm: "xorg-x11-server-Xnest~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xorg", rpm: "xorg-x11-server-Xorg~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xvfb", rpm: "xorg-x11-server-Xvfb~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-Xvnc-source", rpm: "xorg-x11-server-Xvnc-source~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-debuginfo", rpm: "xorg-x11-server-debuginfo~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xorg-x11-server-sdk", rpm: "xorg-x11-server-sdk~1.1.1~48.101.el5_10.2", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

