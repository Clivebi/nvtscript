if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704576" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-11037" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 01:15:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:49:42 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4576-1 (php-imagick - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4576.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4576-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-imagick'
  package(s) announced via the DSA-4576-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An out-of-bounds write vulnerability was discovered in php-imagick, a
PHP extension to create and modify images using the ImageMagick API,
which could result in denial of service, or potentially the execution of
arbitrary code." );
	script_tag( name: "affected", value: "'php-imagick' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 3.4.3~rc2-2+deb9u1.

We recommend that you upgrade your php-imagick packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-imagick", ver: "3.4.3~rc2-2+deb9u1", rls: "DEB9" ) )){
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

