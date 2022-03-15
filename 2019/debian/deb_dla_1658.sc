if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891658" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-19968", "CVE-2018-19970" );
	script_name( "Debian LTS: Security Advisory for phpmyadmin (DLA-1658-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-04 00:00:00 +0100 (Mon, 04 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-22 14:10:00 +0000 (Mon, 22 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "phpmyadmin on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4:4.2.12-2+deb8u4.

We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "summary", value: "A couple of vulnerabilities have been discovered in phpmyadmin, MySQL web
administration tool.

CVE-2018-19968

An attacker can exploit phpMyAdmin before 4.8.4 to leak the contents of a
local file because of an error in the transformation feature. The attacker
must have access to the phpMyAdmin Configuration Storage tables, although
these can easily be created in any database to which the attacker has
access. An attacker must have valid credentials to log in to phpMyAdmin.
This vulnerability does not allow an attacker to circumvent the login
system.

CVE-2018-19970

An XSS vulnerability was found in the navigation tree, where an attacker can
deliver a payload to a user through a crafted database/table name." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:4.2.12-2+deb8u4", rls: "DEB8" ) )){
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

