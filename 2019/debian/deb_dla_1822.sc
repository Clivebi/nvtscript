if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891822" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-9858" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-17 00:29:00 +0000 (Mon, 17 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-17 02:00:08 +0000 (Mon, 17 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for php-horde-form (DLA-1822-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1822-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/930321" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde-form'
  package(s) announced via the DLA-1822-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Horde Application Framework contained a remote code execution
vulnerability. A remote attacker could use this flaw to use image
uploads in forms to install and execute a file in an arbitrary
writable location on the server." );
	script_tag( name: "affected", value: "'php-horde-form' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.0.8-2+deb8u1.

We recommend that you upgrade your php-horde-form packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-horde-form", ver: "2.0.8-2+deb8u1", rls: "DEB8" ) )){
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

