if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892301" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_cve_id( "CVE-2020-12762" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 09:15:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2020-07-31 03:00:15 +0000 (Fri, 31 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for json-c (DLA-2301-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00031.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2301-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/960326" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'json-c'
  package(s) announced via the DLA-2301-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Tobias Stoeckmann found an integer overflow issue in JSON-C, a C
library to manipulate JSON objects, when reading maliciously crafted
large files. The issue could be exploited to cause denial of service
or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "'json-c' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.12.1-1.1+deb9u1.

We recommend that you upgrade your json-c packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjson-c-dev", ver: "0.12.1-1.1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjson-c-doc", ver: "0.12.1-1.1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjson-c3", ver: "0.12.1-1.1+deb9u1", rls: "DEB9" ) )){
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

