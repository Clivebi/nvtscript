if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891617" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-6307" );
	script_name( "Debian LTS: Security Advisory for libvncserver (DLA-1617-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-28 00:00:00 +0100 (Fri, 28 Dec 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/12/msg00017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libvncserver on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.9.9+dfsg2-6.1+deb8u4.

We recommend that you upgrade your libvncserver packages." );
	script_tag( name: "summary", value: "Kaspersky Lab discovered several vulnerabilities in libvncserver, a C
library to implement VNC server/client functionalities.

CVE-2018-6307

a heap use-after-free vulnerability in the server code of the file
transfer extension, which can result in remote code execution. This
attack appears to be exploitable via network connectivity.

CVE-2018-15127

contains a heap out-of-bound write vulnerability in the server code
of the file transfer extension, which can result in remote code
execution. This attack appears to be exploitable via network
connectivity.

CVE-2018-20019

multiple heap out-of-bound write vulnerabilities in VNC client code,
which can result in remote code execution.

CVE-2018-20020

heap out-of-bound write vulnerability in a structure in VNC client
code, which can result in remote code execution.

CVE-2018-20021

CWE-835: Infinite Loop vulnerability in VNC client code. The
vulnerability could allow an attacker to consume an excessive amount
of resources, such as CPU and RAM.

CVE-2018-20022

CWE-665: Improper Initialization weaknesses in VNC client code,
which could allow an attacker to read stack memory and can be abused
for information disclosure. Combined with another vulnerability, it
can be used to leak stack memory layout and bypass ASLR.

CVE-2018-20023

Improper Initialization vulnerability in VNC Repeater client code,
which could allow an attacker to read stack memory and can be abused
for information disclosure. Combined with another vulnerability, it
can be used to leak stack memory layout and bypass ASLR.

CVE-2018-20024

a null pointer dereference in VNC client code, which can result in
DoS." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-config", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-dev", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linuxvnc", ver: "0.9.9+dfsg2-6.1+deb8u4", rls: "DEB8" ) )){
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

