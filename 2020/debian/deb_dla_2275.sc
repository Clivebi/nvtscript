if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892275" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-8161", "CVE-2020-8184" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 23:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-07-17 12:33:12 +0000 (Fri, 17 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-rack (DLA-2275-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00006.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2275-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/963477" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-rack'
  package(s) announced via the DLA-2275-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following CVEs were reported against src:ruby-rack.

CVE-2020-8161

A directory traversal vulnerability exists in rack < 2.2.0 that
allows an attacker perform directory traversal vulnerability in
the Rack::Directory app that is bundled with Rack which could
result in information disclosure.

CVE-2020-8184

A reliance on cookies without validation/integrity check security
vulnerability exists in rack < 2.2.3, rack < 2.1.4 that makes it
is possible for an attacker to forge a secure or host-only cookie
prefix." );
	script_tag( name: "affected", value: "'ruby-rack' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.6.4-4+deb9u2.

We recommend that you upgrade your ruby-rack packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-rack", ver: "1.6.4-4+deb9u2", rls: "DEB9" ) )){
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

