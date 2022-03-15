if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891644" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2018-19788", "CVE-2019-6133" );
	script_name( "Debian LTS: Security Advisory for policykit-1 (DLA-1644-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-28 00:00:00 +0100 (Mon, 28 Jan 2019)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "policykit-1 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.105-15~deb8u4.

We recommend that you upgrade your policykit-1 packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were found in Policykit, a framework for managing
administrative policies and privileges:

CVE-2018-19788

It was discovered that incorrect processing of very high UIDs in
Policykit could result in authentication bypass.

CVE-2019-6133

Jann Horn of Google found that Policykit doesn't properly check
if a process is already authenticated, which can lead to an
authentication reuse by a different user." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-polkit-1.0", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpolkit-agent-1-0", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpolkit-agent-1-dev", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpolkit-backend-1-dev", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpolkit-gobject-1-0", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpolkit-gobject-1-dev", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "policykit-1", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "policykit-1-doc", ver: "0.105-15~deb8u4", rls: "DEB8" ) )){
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

