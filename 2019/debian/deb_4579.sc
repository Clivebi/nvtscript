if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704579" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-11745", "CVE-2019-17007" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:22:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-12-09 03:00:05 +0000 (Mon, 09 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4579-1 (nss - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4579.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4579-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the DSA-4579-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in NSS, a set of cryptographic
libraries, which may result in denial of service and potentially the
execution of arbitrary code." );
	script_tag( name: "affected", value: "'nss' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2:3.42.1-1+deb10u2.

We recommend that you upgrade your nss packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.42.1-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.42.1-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.42.1-1+deb10u2", rls: "DEB10" ) )){
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

