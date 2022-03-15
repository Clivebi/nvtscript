if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891763" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-9894", "CVE-2019-9897", "CVE-2019-9898" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 14:11:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-25 02:00:10 +0000 (Thu, 25 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for putty (DLA-1763-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1763-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'putty'
  package(s) announced via the DLA-1763-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were found in the PuTTY SSH client, which could
result in denial of service and potentially the execution of arbitrary
code. In addition, in some situations random numbers could potentially be
re-used." );
	script_tag( name: "affected", value: "'putty' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.63-10+deb8u2.

We recommend that you upgrade your putty packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pterm", ver: "0.63-10+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "putty", ver: "0.63-10+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "putty-doc", ver: "0.63-10+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "putty-tools", ver: "0.63-10+deb8u2", rls: "DEB8" ) )){
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

