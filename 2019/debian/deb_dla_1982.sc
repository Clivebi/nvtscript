if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891982" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-18601", "CVE-2019-18602", "CVE-2019-18603" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 02:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-06 03:00:23 +0000 (Wed, 06 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for openafs (DLA-1982-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1982-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/943587" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openafs'
  package(s) announced via the DLA-1982-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities were discovered in OpenAFS, a
distributed file system.

CVE-2019-18601

OpenAFS is prone to denial of service from unserialized data access
because remote attackers can make a series of VOTE_Debug RPC calls
to crash a database server within the SVOTE_Debug RPC handler.

CVE-2019-18602

OpenAFS is prone to an information disclosure vulnerability because
uninitialized scalars are sent over the network to a peer.

CVE-2019-18603

OpenAFS is prone to information leakage upon certain error
conditions because uninitialized RPC output variables are sent over
the network to a peer." );
	script_tag( name: "affected", value: "'openafs' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.6.9-2+deb8u9.

We recommend that you upgrade your openafs packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libafsauthent1", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libafsrpc1", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkopenafs1", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenafs-dev", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-openafs-kaserver", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-client", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-dbg", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-dbserver", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-doc", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-fileserver", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-fuse", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-kpasswd", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-krb5", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-modules-dkms", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openafs-modules-source", ver: "1.6.9-2+deb8u9", rls: "DEB8" ) )){
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

