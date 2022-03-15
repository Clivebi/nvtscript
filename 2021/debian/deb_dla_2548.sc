if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892548" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-35502", "CVE-2021-20209", "CVE-2021-20210", "CVE-2021-20211", "CVE-2021-20212", "CVE-2021-20213", "CVE-2021-20215", "CVE-2021-20216", "CVE-2021-20217" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 07:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-07 04:00:23 +0000 (Sun, 07 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for privoxy (DLA-2548-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2548-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2548-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'privoxy'
  package(s) announced via the DLA-2548-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities were discovered in privoxy, a privacy
enhancing HTTP proxy, like memory leaks, dereference of a
NULL-pointer, et al." );
	script_tag( name: "affected", value: "'privoxy' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.0.26-3+deb9u1.

We recommend that you upgrade your privoxy packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "privoxy", ver: "3.0.26-3+deb9u1", rls: "DEB9" ) )){
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
