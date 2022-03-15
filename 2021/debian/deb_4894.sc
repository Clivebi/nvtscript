if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704894" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-36193" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 12:52:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 03:00:06 +0000 (Wed, 21 Apr 2021)" );
	script_name( "Debian: Security Advisory for php-pear (DSA-4894-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4894.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4894-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4894-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-pear'
  package(s) announced via the DSA-4894-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the PEAR Archive_Tar package for handling tar
files in PHP is prone to a directory traversal flaw due to inadequate
checking of symbolic links." );
	script_tag( name: "affected", value: "'php-pear' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1:1.10.6+submodules+notgz-1.1+deb10u2.

We recommend that you upgrade your php-pear packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "1:1.10.6+submodules+notgz-1.1+deb10u2", rls: "DEB10" ) )){
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

