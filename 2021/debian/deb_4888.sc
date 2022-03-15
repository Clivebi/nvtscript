if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704888" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-26933", "CVE-2021-27379" );
	script_tag( name: "cvss_base", value: "5.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-11 12:15:00 +0000 (Sun, 11 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-12 03:00:12 +0000 (Mon, 12 Apr 2021)" );
	script_name( "Debian: Security Advisory for xen (DSA-4888-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4888.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4888-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4888-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the DSA-4888-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor,
which could result in denial of service, privilege escalation or memory
disclosure." );
	script_tag( name: "affected", value: "'xen' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 4.11.4+99-g8bce4698f6-1.

We recommend that you upgrade your xen packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxencall1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxendevicemodel1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenevtchn1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenforeignmemory1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxengnttab1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenmisc4.11", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxentoolcore1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxentoollog1", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-doc", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.11-amd64", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.11-arm64", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.11-armhf", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-common", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.11", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.11.4+99-g8bce4698f6-1", rls: "DEB10" ) )){
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

