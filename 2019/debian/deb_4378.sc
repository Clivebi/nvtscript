if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704378" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-1000888" );
	script_name( "Debian Security Advisory DSA 4378-1 (php-pear - security update)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-30 00:00:00 +0100 (Wed, 30 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-15 18:15:00 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4378.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "php-pear on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1:1.10.1+submodules+notgz-9+deb9u1.

We recommend that you upgrade your php-pear packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/php-pear" );
	script_tag( name: "summary", value: "Fariskhi Vidyan discovered that the PEAR Archive_Tar package for
handling tar files in PHP is prone to a PHP object injection
vulnerability, potentially allowing a remote attacker to execute
arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "1:1.10.1+submodules+notgz-9+deb9u1", rls: "DEB9" ) )){
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

