if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892546" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 19:28:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-06 04:00:07 +0000 (Sat, 06 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for intel-microcode (DLA-2546-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2546-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2546-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the DLA-2546-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2020-8695

Observable discrepancy in the RAPL interface for some
Intel(R) Processors may allow a privileged user to
potentially enable information disclosure via local access.

CVE-2020-8696

Improper removal of sensitive information before storage
or transfer in some Intel(R) Processors may allow an
authenticated user to potentially enable information
disclosure via local access.

CVE-2020-8698

Improper isolation of shared resources in some
Intel(R) Processors may allow an authenticated user to
potentially enable information disclosure via local access." );
	script_tag( name: "affected", value: "'intel-microcode' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.20201118.1~deb9u1.

We recommend that you upgrade your intel-microcode packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20201118.1~deb9u1", rls: "DEB9" ) )){
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

