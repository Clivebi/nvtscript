if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892738" );
	script_version( "2021-08-13T11:44:16+0000" );
	script_cve_id( "CVE-2021-3672" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 11:44:16 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 09:50:22 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for c-ares (DLA-2738-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2738-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2738-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'c-ares'
  package(s) announced via the DLA-2738-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in c-ares, an asynchronous name resolver.
Missing input validation of host names returned by Domain Name Servers can
lead to output of wrong hostnames." );
	script_tag( name: "affected", value: "'c-ares' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.12.0-1+deb9u2.

We recommend that you upgrade your c-ares packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libc-ares-dev", ver: "1.12.0-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libc-ares2", ver: "1.12.0-1+deb9u2", rls: "DEB9" ) )){
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

