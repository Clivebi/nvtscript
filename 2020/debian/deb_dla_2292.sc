if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892292" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_cve_id( "CVE-2019-14464", "CVE-2019-14496", "CVE-2019-14497", "CVE-2020-15569" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 00:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-07-28 03:00:12 +0000 (Tue, 28 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for milkytracker (DLA-2292-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2292-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/933964" );
	script_xref( name: "URL", value: "https://bugs.debian.org/964797" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'milkytracker'
  package(s) announced via the DLA-2292-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were fixed in MilkyTracker, a music tracker for
composing music in the MOD and XM module file formats.

CVE-2019-14464

Heap-based buffer overflow in XMFile::read

CVE-2019-14496

Stack-based buffer overflow in LoaderXM::load

CVE-2019-14497

Heap-based buffer overflow in ModuleEditor::convertInstrument

CVE-2020-15569

Use-after-free in the PlayerGeneric destructor" );
	script_tag( name: "affected", value: "'milkytracker' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
0.90.86+dfsg-2+deb9u1.

We recommend that you upgrade your milkytracker packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "milkytracker", ver: "0.90.86+dfsg-2+deb9u1", rls: "DEB9" ) )){
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

