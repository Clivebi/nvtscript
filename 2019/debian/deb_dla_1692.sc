if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891692" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-6799" );
	script_name( "Debian LTS: Security Advisory for phpmyadmin (DLA-1692-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-27 00:00:00 +0100 (Wed, 27 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00039.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "phpmyadmin on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4:4.2.12-2+deb8u5.

We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "summary", value: "n information leak issue was discovered in phpMyAdmin. An attacker
can read any file on the server that the web server's user can
access. This is related to the mysql.allow_local_infile PHP
configuration. When the AllowArbitraryServer configuration setting is
set to false (default), the attacker needs a local MySQL account. When
set to true, the attacker can exploit this with the use of a rogue
MySQL server." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:4.2.12-2+deb8u5", rls: "DEB8" ) )){
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

