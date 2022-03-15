if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704276" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2017-14650", "CVE-2017-9773", "CVE-2017-9774" );
	script_name( "Debian Security Advisory DSA 4276-1 (php-horde-image - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-17 00:00:00 +0200 (Fri, 17 Aug 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-18 10:29:00 +0000 (Sat, 18 Aug 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4276.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "php-horde-image on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2.3.6-1+deb9u1.

We recommend that you upgrade your php-horde-image packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/php-horde-image" );
	script_tag( name: "summary", value: "Fariskhi Vidyan and Thomas Jarosch discovered several vulnerabilities
in php-horde-image, the image processing library for the Horde
groupware suite. They would allow an attacker to cause a
denial-of-service or execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-horde-image", ver: "2.3.6-1+deb9u1", rls: "DEB9" ) )){
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

