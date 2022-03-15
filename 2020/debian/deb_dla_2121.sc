if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892121" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2016-5104" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2020-02-28 04:00:09 +0000 (Fri, 28 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for libimobiledevice (DLA-2121-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00027.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2121-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/825553" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libimobiledevice'
  package(s) announced via the DLA-2121-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libimobiledevice incorrectly handled socket
permissions. A remote attacker could use this issue to access
services on iOS devices, contrary to expectations." );
	script_tag( name: "affected", value: "'libimobiledevice' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.1.6+dfsg-3.1+deb8u1.

We recommend that you upgrade your libimobiledevice packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libimobiledevice-dev", ver: "1.1.6+dfsg-3.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimobiledevice-doc", ver: "1.1.6+dfsg-3.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimobiledevice-utils", ver: "1.1.6+dfsg-3.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimobiledevice4", ver: "1.1.6+dfsg-3.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libimobiledevice4-dbg", ver: "1.1.6+dfsg-3.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-imobiledevice", ver: "1.1.6+dfsg-3.1+deb8u1", rls: "DEB8" ) )){
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

