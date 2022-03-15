if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704869" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-35523", "CVE-2020-35524" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-28 02:15:00 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-14 04:00:06 +0000 (Sun, 14 Mar 2021)" );
	script_name( "Debian: Security Advisory for tiff (DSA-4869-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4869.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4869-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4869-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff'
  package(s) announced via the DSA-4869-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in the libtiff library
and the included tools, which may result in denial of service or the
execution of arbitrary code if malformed image files are processed." );
	script_tag( name: "affected", value: "'tiff' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 4.1.0+git191117-2~deb10u2.

We recommend that you upgrade your tiff packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff-dev", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-doc", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-tools", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5-dev", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx5", ver: "4.1.0+git191117-2~deb10u2", rls: "DEB10" ) )){
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

