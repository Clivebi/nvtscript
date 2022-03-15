if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892556" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-12662", "CVE-2020-12663", "CVE-2020-28935" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 21:00:00 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-14 04:00:22 +0000 (Sun, 14 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for unbound1.9 (DLA-2556-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00017.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2556-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2556-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/977165" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unbound1.9'
  package(s) announced via the DLA-2556-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities have been corrected in unbound, a
validating, recursive, caching DNS resolver. Support for the unbound DNS server
has been resumed, the sources can be found in the unbound1.9 source package.

CVE-2020-12662

Unbound has Insufficient Control of Network Message
Volume, aka an 'NXNSAttack' issue. This is triggered by random
subdomains in the NSDNAME in NS records.

CVE-2020-12663

Unbound has an infinite loop via malformed DNS answers received from
upstream servers.

CVE-2020-28935

Unbound contains a local vulnerability that would allow for a local symlink
attack. When writing the PID file Unbound creates the file if it is not
there, or opens an existing file for writing. In case the file was already
present, it would follow symlinks if the file happened to be a symlink
instead of a regular file." );
	script_tag( name: "affected", value: "'unbound1.9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.9.0-2+deb10u2~deb9u1.

We recommend that you upgrade your unbound1.9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libunbound8", ver: "1.9.0-2+deb10u2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound", ver: "1.9.0-2+deb10u2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound-anchor", ver: "1.9.0-2+deb10u2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound-host", ver: "1.9.0-2+deb10u2~deb9u1", rls: "DEB9" ) )){
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

