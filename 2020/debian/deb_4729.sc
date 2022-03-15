if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704729" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-14380", "CVE-2019-17113" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-02 01:15:00 +0000 (Sun, 02 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-21 03:01:21 +0000 (Tue, 21 Jul 2020)" );
	script_name( "Debian: Security Advisory for libopenmpt (DSA-4729-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4729.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4729-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the DSA-4729-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security issues were found in libopenmpt, a cross-platform C++ and
C library to decode tracked music files, which could result in denial of
service and potentially the execution of arbitrary code if malformed music
files are processed." );
	script_tag( name: "affected", value: "'libopenmpt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 0.4.3-1+deb10u1.

We recommend that you upgrade your libopenmpt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-dev", ver: "0.4.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-doc", ver: "0.4.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-modplug-dev", ver: "0.4.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt-modplug1", ver: "0.4.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenmpt0", ver: "0.4.3-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openmpt123", ver: "0.4.3-1+deb10u1", rls: "DEB10" ) )){
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

