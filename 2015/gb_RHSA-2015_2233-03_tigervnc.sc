if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871497" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-20 06:24:24 +0100 (Fri, 20 Nov 2015)" );
	script_cve_id( "CVE-2014-8240", "CVE-2014-8241" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for tigervnc RHSA-2015:2233-03" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tigervnc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Virtual Network Computing (VNC) is a remote
display system which allows users to view a computing desktop environment not
only on the machine where it is running, but from anywhere on the Internet and
from a wide variety of machine architectures. TigerVNC is a suite of VNC servers
and clients. The tigervnc packages contain a client which allows users to connect
to other desktops running a VNC server.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way TigerVNC handled screen sizes. A malicious VNC server
could use this flaw to cause a client to crash or, potentially, execute
arbitrary code on the client. (CVE-2014-8240)

A NULL pointer dereference flaw was found in TigerVNC's XRegion.
A malicious VNC server could use this flaw to cause a client to crash.
(CVE-2014-8241)

The tigervnc packages have been upgraded to upstream version 1.3.1, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#1199453)

This update also fixes the following bug:

  * The position of the mouse cursor in the VNC session was not correctly
communicated to the VNC viewer, resulting in cursor misplacement.
The method of displaying the remote cursor has been changed, and cursor
movements on the VNC server are now accurately reflected on the VNC client.
(BZ#1100661)

All tigervnc users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements." );
	script_tag( name: "affected", value: "tigervnc on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:2233-03" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-November/msg00033.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "tigervnc-icons", rpm: "tigervnc-icons~1.3.1~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-license", rpm: "tigervnc-license~1.3.1~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc", rpm: "tigervnc~1.3.1~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-debuginfo", rpm: "tigervnc-debuginfo~1.3.1~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-server", rpm: "tigervnc-server~1.3.1~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-server-minimal", rpm: "tigervnc-server-minimal~1.3.1~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

