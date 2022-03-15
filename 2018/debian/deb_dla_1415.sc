if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891415" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2016-6609", "CVE-2016-6614", "CVE-2016-6615", "CVE-2016-6616", "CVE-2016-6618", "CVE-2016-6619", "CVE-2016-6620", "CVE-2016-6621", "CVE-2016-6622", "CVE-2016-9865", "CVE-2017-18264" );
	script_name( "Debian LTS: Security Advisory for phpmyadmin (DLA-1415-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00006.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "phpmyadmin on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4:4.2.12-2+deb8u3.

We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were found in phpMyAdmin, the web-based MySQL
administration interface, including SQL injection attacks, denial of
service, arbitrary code execution, cross-site scripting, server-side
request forgery, authentication bypass, and file system traversal." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:4.2.12-2+deb8u3", rls: "DEB8" ) )){
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

