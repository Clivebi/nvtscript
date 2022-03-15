if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891797" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_cve_id( "CVE-2019-11358", "CVE-2019-11831" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-29 16:29:00 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-21 02:00:26 +0000 (Tue, 21 May 2019)" );
	script_name( "Debian LTS: Security Advisory for drupal7 (DLA-1797-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1797-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/927330" );
	script_xref( name: "URL", value: "https://bugs.debian.org/928688" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-006" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-007" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the DLA-1797-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities have been discovered in drupal7, a
PHP web site platform. The vulnerabilities affect the embedded versions
of the jQuery JavaScript library and the Typo3 Phar Stream Wrapper
library.

CVE-2019-11358

It was discovered that the jQuery version embedded in Drupal was
prone to a cross site scripting vulnerability in jQuery.extend().

CVE-2019-11831

It was discovered that incomplete validation in a Phar processing
library embedded in Drupal, a fully-featured content management
framework, could result in information disclosure.

For additional information, please see the referenced upstream advisories." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
7.32-1+deb8u17.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u17", rls: "DEB8" ) )){
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
