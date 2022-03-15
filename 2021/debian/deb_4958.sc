if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704958" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2019-20421", "CVE-2021-29457", "CVE-2021-29473", "CVE-2021-31292", "CVE-2021-3482" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-26 17:44:00 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2021-08-15 03:00:11 +0000 (Sun, 15 Aug 2021)" );
	script_name( "Debian: Security Advisory for exiv2 (DSA-4958-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4958.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4958-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4958-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2'
  package(s) announced via the DSA-4958-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Exiv2, a C++ library and
a command line utility to manage image metadata which could result in
denial of service or the execution of arbitrary code if a malformed
file is parsed." );
	script_tag( name: "affected", value: "'exiv2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 0.25-4+deb10u2.

We recommend that you upgrade your exiv2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.25-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-14", ver: "0.25-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dev", ver: "0.25-4+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-doc", ver: "0.25-4+deb10u2", rls: "DEB10" ) )){
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

