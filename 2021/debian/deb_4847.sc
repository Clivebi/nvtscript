if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704847" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-26675", "CVE-2021-26676" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-10 04:00:31 +0000 (Wed, 10 Feb 2021)" );
	script_name( "Debian: Security Advisory for connman (DSA-4847-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4847.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4847-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4847-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'connman'
  package(s) announced via the DSA-4847-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A remote information leak vulnerability and a remote buffer overflow
vulnerability were discovered in ConnMan, a network manager for embedded
devices, which could result in denial of service or the execution of
arbitrary code." );
	script_tag( name: "affected", value: "'connman' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1.36-2.1~deb10u1.

We recommend that you upgrade your connman packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "connman", ver: "1.36-2.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "connman-dev", ver: "1.36-2.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "connman-doc", ver: "1.36-2.1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "connman-vpn", ver: "1.36-2.1~deb10u1", rls: "DEB10" ) )){
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
