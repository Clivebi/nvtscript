if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891513" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949" );
	script_name( "Debian LTS: Security Advisory for openafs (DLA-1513-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-24 00:00:00 +0200 (Mon, 24 Sep 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openafs on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.6.9-2+deb8u8.

We recommend that you upgrade your openafs packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were discovered in OpenAFS, a
distributed file system.

CVE-2018-16947

The backup tape controller process accepts incoming RPCs but does
not require (or allow for) authentication of those RPCs. Handling
those RPCs results in operations being performed with administrator
credentials, including dumping/restoring volume contents and
manipulating the backup database.

CVE-2018-16948

Several RPC server routines did not fully initialize their output
variables before returning, leaking memory contents from both the
stack and the heap. Because the OpenAFS cache manager functions as
an Rx server for the AFSCB service, clients are also susceptible to
information leakage.

CVE-2018-16949

Several data types used as RPC input variables were implemented as
unbounded array types, limited only by the inherent 32-bit length
field to 4GB. An unauthenticated attacker could send, or claim to
send, large input values and consume server resources waiting for
those inputs, denying service to other valid connections." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libafsauthent1", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libafsrpc1", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkopenafs1", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-client", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-fuse", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.6.9-2+deb8u8", rls: "DEB8" ) )){
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

