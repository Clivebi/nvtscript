if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891241" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2016-10510" );
	script_name( "Debian LTS: Security Advisory for libkohana2-php (DLA-1241-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-16 00:00:00 +0100 (Tue, 16 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 20:15:00 +0000 (Wed, 31 Mar 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libkohana2-php on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.3.4-2+deb7u1.

We recommend that you upgrade your libkohana2-php packages." );
	script_tag( name: "summary", value: "David Sopas discovered that Kohana, a PHP framework, was vulnerable to
a Cross-site scripting (XSS) attack that allowed remote attackers to
inject arbitrary web script or HTML by bypassing the strip_image_tags
protection mechanism in system/classes/Kohana/Security.php. This issue
was resolved by permanently removing the strip_image_tags function.
Users are advised to sanitize user input by using external libraries
instead." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libkohana2-modules-php", ver: "2.3.4-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkohana2-php", ver: "2.3.4-2+deb7u1", rls: "DEB7" ) )){
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

