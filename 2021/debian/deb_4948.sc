if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704948" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2019-17544", "CVE-2019-25051" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-19 21:15:00 +0000 (Sat, 19 Oct 2019)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:00:07 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Debian: Security Advisory for aspell (DSA-4948-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4948.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4948-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4948-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aspell'
  package(s) announced via the DSA-4948-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A buffer overflow was discovered in the Aspell spell checker, which could
result in the execution of arbitrary code." );
	script_tag( name: "affected", value: "'aspell' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 0.60.7~20110707-6+deb10u1.

We recommend that you upgrade your aspell packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "aspell", ver: "0.60.7~20110707-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "aspell-doc", ver: "0.60.7~20110707-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaspell-dev", ver: "0.60.7~20110707-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaspell15", ver: "0.60.7~20110707-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpspell-dev", ver: "0.60.7~20110707-6+deb10u1", rls: "DEB10" ) )){
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

