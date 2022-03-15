if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891941" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-16869" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 16:22:00 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2019-10-01 02:00:14 +0000 (Tue, 01 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for netty (DLA-1941-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00035.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1941-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netty'
  package(s) announced via the DLA-1941-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Netty mishandled whitespace before the colon in HTTP headers (such as a
'Transfer-Encoding : chunked' line), which lead to HTTP request
smuggling." );
	script_tag( name: "affected", value: "'netty' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1:3.2.6.Final-2+deb8u1.

We recommend that you upgrade your netty packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnetty-java", ver: "1:3.2.6.Final-2+deb8u1", rls: "DEB8" ) )){
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

