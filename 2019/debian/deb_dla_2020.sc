if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892020" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-19012", "CVE-2019-19204", "CVE-2019-19246" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-05 03:00:09 +0000 (Thu, 05 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for libonig (DLA-2020-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2020-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/944959" );
	script_xref( name: "URL", value: "https://bugs.debian.org/945313" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libonig'
  package(s) announced via the DLA-2020-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Oniguruma regular
expressions library, notably used in PHP mbstring.

CVE-2019-19012

An integer overflow in the search_in_range function in regexec.c
leads to an out-of-bounds read, in which the offset of this read
is under the control of an attacker. (This only affects the 32-bit
compiled version). Remote attackers can cause a denial-of-service
or information disclosure, or possibly have unspecified other
impact, via a crafted regular expression.

CVE-2019-19204

In the function fetch_range_quantifier in regparse.c, PFETCH is
called without checking PEND. This leads to a heap-based buffer
over-read and lead to denial-of-service via a crafted regular
expression.

CVE-2019-19246

Heap-based buffer over-read in str_lower_case_match in regexec.c
can lead to denial-of-service via a crafted regular expression." );
	script_tag( name: "affected", value: "'libonig' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.9.5-3.2+deb8u4.

We recommend that you upgrade your libonig packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libonig-dev", ver: "5.9.5-3.2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libonig2", ver: "5.9.5-3.2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libonig2-dbg", ver: "5.9.5-3.2+deb8u4", rls: "DEB8" ) )){
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

