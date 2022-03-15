if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892725" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2017-8844", "CVE-2017-8846", "CVE-2017-9928", "CVE-2017-9929", "CVE-2018-10685", "CVE-2018-11496", "CVE-2018-5650", "CVE-2018-5747", "CVE-2018-5786" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-06 15:17:00 +0000 (Wed, 06 Jun 2018)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:00:25 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for lrzip (DLA-2725-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2725-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2725-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lrzip'
  package(s) announced via the DLA-2725-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities have been discovered in lrzip, a compression
program. Heap-based and stack buffer overflows, use-after-free and infinite
loops would allow attackers to cause a denial of service or possibly other
unspecified impact via a crafted file." );
	script_tag( name: "affected", value: "'lrzip' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
0.631-1+deb9u1.

We recommend that you upgrade your lrzip packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lrzip", ver: "0.631-1+deb9u1", rls: "DEB9" ) )){
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

