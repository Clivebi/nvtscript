if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871112" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-01-21 13:42:52 +0530 (Tue, 21 Jan 2014)" );
	script_cve_id( "CVE-2013-6462" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "RedHat Update for libXfont RHSA-2014:0018-01" );
	script_tag( name: "affected", value: "libXfont on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "The libXfont packages provide the X.Org libXfont runtime library. X.Org is
an open source implementation of the X Window System.

A stack-based buffer overflow flaw was found in the way the libXfont
library parsed Glyph Bitmap Distribution Format (BDF) fonts. A malicious,
local user could exploit this issue to potentially execute arbitrary code
with the privileges of the X.Org server. (CVE-2013-6462)

Users of libXfont should upgrade to these updated packages, which contain
a backported patch to resolve this issue. All running X.Org server
instances must be restarted for the update to take effect." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:0018-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-January/msg00006.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "libXfont", rpm: "libXfont~1.4.5~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libXfont-debuginfo", rpm: "libXfont-debuginfo~1.4.5~3.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "libXfont", rpm: "libXfont~1.2.2~1.0.5.el5_10", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libXfont-debuginfo", rpm: "libXfont-debuginfo~1.2.2~1.0.5.el5_10", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libXfont-devel", rpm: "libXfont-devel~1.2.2~1.0.5.el5_10", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

