if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892005" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-18849" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-23 16:15:00 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-11-30 03:00:17 +0000 (Sat, 30 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for tnef (DLA-2005-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00035.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2005-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/944851" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tnef'
  package(s) announced via the DLA-2005-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In tnef, an attacker may be able to write to the victim's
.ssh/authorized_keys file via an e-mail message with a crafted
winmail.dat application/ms-tnef attachment, because of a heap-based
buffer over-read involving strdup." );
	script_tag( name: "affected", value: "'tnef' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.4.9-1+deb8u4.

We recommend that you upgrade your tnef packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tnef", ver: "1.4.9-1+deb8u4", rls: "DEB8" ) )){
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

