if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704926" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-28091" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 03:15:00 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-05 03:00:08 +0000 (Sat, 05 Jun 2021)" );
	script_name( "Debian: Security Advisory for lasso (DSA-4926-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4926.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4926-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4926-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lasso'
  package(s) announced via the DSA-4926-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that lasso, a library which implements SAML 2.0 and
Liberty Alliance standards, did not properly verify that all assertions
in a SAML response were properly signed, allowing an attacker to
impersonate users or bypass access control." );
	script_tag( name: "affected", value: "'lasso' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2.6.0-2+deb10u1.

We recommend that you upgrade your lasso packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblasso-perl", ver: "2.6.0-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblasso3", ver: "2.6.0-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblasso3-dev", ver: "2.6.0-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lasso", ver: "2.6.0-2+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lasso", ver: "2.6.0-2+deb10u1", rls: "DEB10" ) )){
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

