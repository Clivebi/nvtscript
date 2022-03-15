if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892718" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 18:46:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-27 03:00:13 +0000 (Tue, 27 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for intel-microcode (DLA-2718-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2718-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2718-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the DLA-2718-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update ships updated CPU microcode for some types of Intel CPUs
and provides mitigations for security vulnerabilities which could
result in privilege escalation in combination with VT-d and various
side channel attacks." );
	script_tag( name: "affected", value: "'intel-microcode' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.20210608.2~deb9u2.

Please note that one of the processors is not receiving this update
and so the users of 0x906ea processors that don't have Intel Wireless
on-board can use the package from the buster-security, instead.

We recommend that you upgrade your intel-microcode packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "intel-microcode", ver: "3.20210608.2~deb9u2", rls: "DEB9" ) )){
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
