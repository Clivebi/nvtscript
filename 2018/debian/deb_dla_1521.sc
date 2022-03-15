if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891521" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-16586", "CVE-2018-16587" );
	script_name( "Debian LTS: Security Advisory for otrs2 (DLA-1521-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-27 00:00:00 +0200 (Thu, 27 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-21 17:55:00 +0000 (Wed, 21 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00033.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "otrs2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u6.

We recommend that you upgrade your otrs2 packages." );
	script_tag( name: "summary", value: "Fabien Arnoux discovered several security issues in email validation
of otrs system.

CVE-2018-16586

Load external image or CSS resources in browser when user opens a
malicious email.

CVE-2018-16587

Remote deletions of arbitrary files that the OTRS web server user
has write access when opening malicious email." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "otrs", ver: "3.3.18-1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "otrs2", ver: "3.3.18-1+deb8u6", rls: "DEB8" ) )){
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

