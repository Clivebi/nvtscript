if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890975" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-8295", "CVE-2017-9061", "CVE-2017-9062", "CVE-2017-9063", "CVE-2017-9064", "CVE-2017-9065" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-975-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-15 12:35:00 +0000 (Fri, 15 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u15.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2017-8295

    Potential unauthorized password reset vulnerability.

CVE-2017-9061

    A cross-site scripting (XSS) vulnerability exists when someone
    attempts to upload very large files.

CVE-2017-9062

    Improper handling of post meta data values in the XML-RPC API.

CVE-2017-9063

   Cross-site scripting (XSS) vulnerability in the customizer.

CVE-2017-9064

    A Cross Site Request Forgery (CSRF) vulnerability exists in the
    filesystem credentials dialog.

CVE-2017-9065

    Lack of capability checks for post meta data in the XML-RPC API." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "3.6.1+dfsg-1~deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.6.1+dfsg-1~deb7u15", rls: "DEB7" ) )){
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

