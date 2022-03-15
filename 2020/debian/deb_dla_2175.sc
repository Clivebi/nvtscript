if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892175" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-8865" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-15 05:15:00 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-16 03:00:09 +0000 (Thu, 16 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for php-horde-trean (DLA-2175-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2175-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/955019" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde-trean'
  package(s) announced via the DLA-2175-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A directory traversal vulnerability resulting from insufficient input
sanitization was discovered in the Horde Application Framework. An
authenticated remote attacker could use this flaw to execute code in the
context of the web server user." );
	script_tag( name: "affected", value: "'php-horde-trean' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.1.1-2+deb8u1.

We recommend that you upgrade your php-horde-trean packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-horde-trean", ver: "1.1.1-2+deb8u1", rls: "DEB8" ) )){
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

