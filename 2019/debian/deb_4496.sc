if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704496" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-1010238" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-14 15:41:00 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-08-12 02:00:17 +0000 (Mon, 12 Aug 2019)" );
	script_name( "Debian Security Advisory DSA 4496-1 (pango1.0 - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4496.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4496-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pango1.0'
  package(s) announced via the DSA-4496-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Benno Fuenfstueck discovered that Pango, a library for layout and
rendering of text with an emphasis on internationalization, is prone to a
heap-based buffer overflow flaw in the pango_log2vis_get_embedding_levels
function. An attacker can take advantage of this flaw for denial of
service or potentially the execution of arbitrary code." );
	script_tag( name: "affected", value: "'pango1.0' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.42.4-7~deb10u1.

We recommend that you upgrade your pango1.0 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-pango-1.0", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpango-1.0-0", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpango1.0-0", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpango1.0-dev", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpango1.0-doc", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpangocairo-1.0-0", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpangoft2-1.0-0", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpangoxft-1.0-0", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pango1.0-tests", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pango1.0-tools", ver: "1.42.4-7~deb10u1", rls: "DEB10" ) )){
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

