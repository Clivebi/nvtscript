if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704920" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-31535" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:46:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-25 03:00:05 +0000 (Tue, 25 May 2021)" );
	script_name( "Debian: Security Advisory for libx11 (DSA-4920-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4920.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4920-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4920-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libx11'
  package(s) announced via the DSA-4920-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Roman Fiedler reported that missing length validation in various
functions provided by libx11, the X11 client-side library, allow
to inject X11 protocol commands on X clients, leading to
authentication bypass, denial of service or potentially the
execution of arbitrary code." );
	script_tag( name: "affected", value: "'libx11' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2:1.6.7-1+deb10u2.

We recommend that you upgrade your libx11 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libx11-6", ver: "2:1.6.7-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-data", ver: "2:1.6.7-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-dev", ver: "2:1.6.7-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-doc", ver: "2:1.6.7-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-xcb-dev", ver: "2:1.6.7-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libx11-xcb1", ver: "2:1.6.7-1+deb10u2", rls: "DEB10" ) )){
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

