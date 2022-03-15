if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892637" );
	script_version( "2021-04-24T03:02:42+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-24 03:02:42 +0000 (Sat, 24 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-24 03:02:42 +0000 (Sat, 24 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for drupal7 (DLA-2637-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2637-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2637-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the DLA-2637-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Drupal project identified a vulnerability in the sanitization
performed in the _filter_xss_arttributes function, potentially
allowing a cross-site scripting, and granted it the Drupal Security
Advisory ID SA-CORE-2021-002:

No CVE number has been announced." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', the fix to this issue was backported in
version 7.52-2+deb9u15.

We recommend you upgrade your drupal7 package.

For detailed security status of drupal7, please refer to its security
tracker page:" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u15", rls: "DEB9" ) )){
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

