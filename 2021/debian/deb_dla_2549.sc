if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892549" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-0256", "CVE-2021-0308" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 14:51:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-09 04:00:26 +0000 (Tue, 09 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for gdisk (DLA-2549-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2549-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2549-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdisk'
  package(s) announced via the DLA-2549-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2020-0256

In LoadPartitionTable of gpt.cc, there is a possible
out of bounds write due to a missing bounds check. This
could lead to local escalation of privilege with no
additional execution privileges needed.

CVE-2021-0308

In ReadLogicalParts of basicmbr.cc, there is a possible
out of bounds write due to a missing bounds check. This
could lead to local escalation of privilege with no
additional execution privileges needed." );
	script_tag( name: "affected", value: "'gdisk' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.0.1-1+deb9u1.

We recommend that you upgrade your gdisk packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gdisk", ver: "1.0.1-1+deb9u1", rls: "DEB9" ) )){
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

