if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892095" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-7040" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 23:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-02-06 04:00:05 +0000 (Thu, 06 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for storebackup (DLA-2095-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2095-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/949393" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'storebackup'
  package(s) announced via the DLA-2095-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "storeBackup.pl in storeBackup through 3.5 relies on the
/tmp/storeBackup.lock pathname, which allows symlink attacks
that possibly lead to privilege escalation.

Local users can also create a plain file named /tmp/storeBackup.lock
to block use of storeBackup until an admin manually deletes that file." );
	script_tag( name: "affected", value: "'storebackup' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.2.1-1+deb8u1.

We recommend that you upgrade your storebackup packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "storebackup", ver: "3.2.1-1+deb8u1", rls: "DEB8" ) )){
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

