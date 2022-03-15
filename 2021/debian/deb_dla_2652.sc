if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892652" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2019-25031", "CVE-2019-25032", "CVE-2019-25033", "CVE-2019-25034", "CVE-2019-25035", "CVE-2019-25036", "CVE-2019-25037", "CVE-2019-25038", "CVE-2019-25039", "CVE-2019-25040", "CVE-2019-25041", "CVE-2019-25042" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 22:15:00 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-07 03:01:32 +0000 (Fri, 07 May 2021)" );
	script_name( "Debian LTS: Security Advisory for unbound1.9 (DLA-2652-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2652-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2652-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unbound1.9'
  package(s) announced via the DLA-2652-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities have been discovered in Unbound, a validating,
recursive, caching DNS resolver, by security researchers of X41 D-SEC located
in Aachen, Germany. Integer overflows, assertion failures, an out-of-bound
write and an infinite loop vulnerability may lead to a denial-of-service or
have a negative impact on data confidentiality." );
	script_tag( name: "affected", value: "'unbound1.9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.9.0-2+deb10u2~deb9u2.

We recommend that you upgrade your unbound1.9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libunbound8", ver: "1.9.0-2+deb10u2~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound", ver: "1.9.0-2+deb10u2~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound-anchor", ver: "1.9.0-2+deb10u2~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "unbound-host", ver: "1.9.0-2+deb10u2~deb9u2", rls: "DEB9" ) )){
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

