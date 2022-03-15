if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881859" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-13 11:39:15 +0530 (Mon, 13 Jan 2014)" );
	script_cve_id( "CVE-2013-6462" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for libXfont CESA-2014:0018 centos6" );
	script_tag( name: "affected", value: "libXfont on CentOS 6" );
	script_tag( name: "insight", value: "The libXfont packages provide the X.Org libXfont runtime library. X.Org is
an open source implementation of the X Window System.

A stack-based buffer overflow flaw was found in the way the libXfont
library parsed Glyph Bitmap Distribution Format (BDF) fonts. A malicious,
local user could exploit this issue to potentially execute arbitrary code
with the privileges of the X.Org server. (CVE-2013-6462)

Users of libXfont should upgrade to these updated packages, which contain
a backported patch to resolve this issue. All running X.Org server
instances must be restarted for the update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0018" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-January/020104.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "libXfont", rpm: "libXfont~1.4.5~3.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libXfont-devel", rpm: "libXfont-devel~1.4.5~3.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

