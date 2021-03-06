if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892775" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_cve_id( "CVE-2021-38714" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-02 14:32:00 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-10-03 01:00:07 +0000 (Sun, 03 Oct 2021)" );
	script_name( "Debian LTS: Security Advisory for plib (DLA-2775-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/10/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2775-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2775-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'plib'
  package(s) announced via the DLA-2775-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "One security issue has been discovered in plib.

Integer overflow vulnerability that could result in arbitrary code execution.
The vulnerability is found in ssgLoadTGA() function in src/ssg/ssgLoadTGA.cxx file." );
	script_tag( name: "affected", value: "'plib' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.8.5-7+deb9u1.

We recommend that you upgrade your plib packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libplib-dev", ver: "1.8.5-7+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplib1", ver: "1.8.5-7+deb9u1", rls: "DEB9" ) )){
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

