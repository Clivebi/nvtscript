if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892621" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-28948", "CVE-2020-36193" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 14:36:00 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-09 03:00:09 +0000 (Fri, 09 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for php-pear (DLA-2621-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2621-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2621-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/980428" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-pear'
  package(s) announced via the DLA-2621-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in php-pear, which provides core
packages from the PHP Extension and Application Repository. Tar.php in
Archive_Tar allows write operations with Directory Traversal due to
inadequate checking of symbolic links, a related issue to
CVE-2020-28948. An attacker could escalate privileges by overwriting
files outside the extraction directory through a crafted .tar archive." );
	script_tag( name: "affected", value: "'php-pear' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1:1.10.1+submodules+notgz-9+deb9u3.

We recommend that you upgrade your php-pear packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "1:1.10.1+submodules+notgz-9+deb9u3", rls: "DEB9" ) )){
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

