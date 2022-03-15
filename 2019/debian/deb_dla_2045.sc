if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892045" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2014-6053", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20748", "CVE-2018-7225", "CVE-2019-15678", "CVE-2019-15679", "CVE-2019-15680", "CVE-2019-15681", "CVE-2019-8287" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-12-22 03:00:17 +0000 (Sun, 22 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for tightvnc (DLA-2045-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2045-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/945364" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tightvnc'
  package(s) announced via the DLA-2045-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have recently been discovered in TightVNC 1.x, an
X11 based VNC server/viewer application for Windows and Unix.

CVE-2014-6053

The rfbProcessClientNormalMessage function in rfbserver.c in TightVNC
server did not properly handle attempts to send a large amount of
ClientCutText data, which allowed remote attackers to cause a denial
of service (memory consumption or daemon crash) via a crafted message
that was processed by using a single unchecked malloc.

CVE-2018-7225

rfbProcessClientNormalMessage() in rfbserver.c did not sanitize
msg.cct.length, leading to access to uninitialized and potentially
sensitive data or possibly unspecified other impact (e.g., an integer
overflow) via specially crafted VNC packets.

CVE-2019-8287

TightVNC code contained global buffer overflow in HandleCoRREBBP
macro function, which could potentially have result in code
execution. This attack appeared to be exploitable via network
connectivity.

(aka CVE-2018-20020/libvncserver)

CVE-2018-20021

TightVNC in vncviewer/rfbproto.c contained a CWE-835: Infinite loop
vulnerability. The vulnerability allowed an attacker to consume
an excessive amount of resources like CPU and RAM.

CVE-2018-20022

TightVNC's vncviewer contained multiple weaknesses CWE-665: Improper
Initialization vulnerability in VNC client code that allowed
attackers to read stack memory and could be abused for information
disclosure. Combined with another vulnerability, it could be used to
leak stack memory layout and in bypassing ASLR.

CVE-2019-15678

TightVNC code version contained heap buffer overflow in
rfbServerCutText handler, which could have potentially resulted in
code execution. This attack appeared to be exploitable via network
connectivity.

(partially aka CVE-2018-20748/libvnvserver)

CVE-2019-15679

TightVNC's vncviewer code contained a heap buffer overflow in
InitialiseRFBConnection function, which could have potentially
resulted in code execution. This attack appeared to be exploitable
via network connectivity.

(partially aka CVE-2018-20748/libvnvserver)

CVE-2019-15680

TightVNC's vncviewer code contained a null pointer dereference in
HandleZlibBPP function, which could have resulted in Denial of System
(DoS). This attack appeared to be exploitable via network
connectivity.

CVE-2019-15681

TightVNC contained a memory leak (CWE-655) in VNC server code, which
allowed an attacker to read stack memory and could have been abused
for information disclosure. Combined with another vulnerability, it
could have been used to leak stack memory and bypass ASLR. This
attack appeared to be exploitable via network connectivity." );
	script_tag( name: "affected", value: "'tightvnc' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.3.9-6.5+deb8u1.

We recommend that you upgrade your tightvnc packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tightvncserver", ver: "1.3.9-6.5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xtightvncviewer", ver: "1.3.9-6.5+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}
exit( 0 );

