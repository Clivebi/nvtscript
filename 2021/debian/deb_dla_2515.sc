if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892515" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2019-15523" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 21:16:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-05 04:00:20 +0000 (Tue, 05 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for csync2 (DLA-2515-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2515-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'csync2'
  package(s) announced via the DLA-2515-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that csync2, a cluster synchronization tool, did
not correctly check for the return value from GnuTLS security
routines. It neglected to repeatedly call this function as required
by the design of the API." );
	script_tag( name: "affected", value: "'csync2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
2.0-8-g175a01c-4+deb9u2.

We recommend that you upgrade your csync2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "csync2", ver: "2.0-8-g175a01c-4+deb9u2", rls: "DEB9" ) )){
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

