if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704785" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2017-18926" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-19 03:15:00 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-08 04:00:05 +0000 (Sun, 08 Nov 2020)" );
	script_name( "Debian: Security Advisory for raptor2 (DSA-4785-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4785.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4785-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'raptor2'
  package(s) announced via the DSA-4785-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that raptor2, an RDF parser library, is prone to
heap-based buffer overflow flaws, which could result in denial of
service, or potentially the execution of arbitrary code, if a specially
crafted file is processed." );
	script_tag( name: "affected", value: "'raptor2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2.0.14-1.1~deb10u1.

We recommend that you upgrade your raptor2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libraptor2-0", ver: "2.0.14-1.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libraptor2-0-dbg", ver: "2.0.14-1.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libraptor2-dev", ver: "2.0.14-1.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libraptor2-doc", ver: "2.0.14-1.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "raptor2-utils", ver: "2.0.14-1.1~deb10u1", rls: "DEB10" ) )){
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

